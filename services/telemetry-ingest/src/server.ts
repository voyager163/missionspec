import { createServer as createHttpServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createProjector } from './contract.js';
import type { Storage } from './contract.js';

export const EVENT_ROUTE = '/v1/events';
export const MAX_BODY_BYTES = 1024;
export const MAX_HEADER_BYTES = 4096;
export const MAX_HEADER_COUNT = 24;
export const STORAGE_RECOVERY_DELAY_MS = 5000;

export interface Limits {
  bodyTimeoutMs: number;
  storageTimeoutMs: number;
  headersTimeoutMs: number;
  maxConnections: number;
  maxConcurrentRequests: number;
  maxConcurrentIngestions: number;
  requestsPerMinute: number;
  eventsPerDay: number;
}

export const limitRanges: Readonly<Record<keyof Limits, readonly [number, number]>> = {
  bodyTimeoutMs: [10, 5000],
  storageTimeoutMs: [10, 5000],
  headersTimeoutMs: [10, 5000],
  maxConnections: [1, 1024],
  maxConcurrentRequests: [1, 256],
  maxConcurrentIngestions: [1, 64],
  requestsPerMinute: [1, 60000],
  eventsPerDay: [1, 1000000],
};

export function validateLimits(limits: Limits): void {
  for (const [key, [min, max]] of Object.entries(limitRanges)) {
    const value = limits[key as keyof Limits];
    if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error('CONFIG_LIMIT_INVALID');
  }
  if (limits.maxConcurrentIngestions > limits.maxConcurrentRequests ||
      limits.maxConcurrentRequests > limits.maxConnections) throw new Error('CONFIG_LIMIT_INVALID');
}

type Code = 'accepted' | 'invalid' | 'oversized' | 'unsupported' | 'not_found' |
  'method' | 'quota' | 'busy' | 'disabled' | 'body_timeout' | 'cancelled' |
  'storage_failure' | 'storage_timeout' | 'http_error';

const repliedSockets = new WeakSet<object>();

function respond(response: ServerResponse, status: number): void {
  if (response.destroyed || response.writableEnded) return;
  if (response.socket) repliedSockets.add(response.socket);
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Length': '0',
    Connection: 'close',
  });
  response.end();
}

class BodyError extends Error {
  constructor(readonly code: 'invalid' | 'oversized' | 'body_timeout' | 'cancelled') {
    super(code);
  }
}

function readBody(request: IncomingMessage, signal: AbortSignal, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    const finish = (error?: BodyError) => {
      clearTimeout(timer);
      request.removeListener('data', data);
      request.removeListener('end', end);
      request.removeListener('error', errorEvent);
      signal.removeEventListener('abort', abort);
      if (error) {
        request.pause();
        chunks.length = 0;
        reject(error);
      } else resolve(Buffer.concat(chunks, size));
    };
    const data = (chunk: Buffer) => {
      size += chunk.byteLength;
      if (size > MAX_BODY_BYTES) finish(new BodyError('oversized'));
      else chunks.push(chunk);
    };
    const end = () => finish();
    const errorEvent = () => finish(new BodyError('invalid'));
    const abort = () => finish(new BodyError('cancelled'));
    const timer = setTimeout(() => finish(new BodyError('body_timeout')), timeoutMs);
    request.on('data', data);
    request.once('end', end);
    request.once('error', errorEvent);
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
  });
}

export interface ReceiverOptions {
  storage: Storage;
  limits: Limits;
  enabled: boolean;
  now?: () => Date;
  monotonicNow?: () => number;
}

/** No listener, credentials, environment access, or network activity until explicitly started. */
export function createTelemetryServer(options: ReceiverOptions) {
  validateLimits(options.limits);
  const { storage, limits } = options;
  const project = createProjector();
  const now = options.now ?? (() => new Date());
  const clock = options.monotonicNow ?? (() => performance.now());
  const counters: Partial<Record<Code, number>> = {};
  const count = (code: Code) => {
    counters[code] = Math.min((counters[code] ?? 0) + 1, Number.MAX_SAFE_INTEGER);
  };
  const active = new Set<AbortController>();
  let enabled = options.enabled;
  let stopping = false;
  let inflightStorage = 0;
  let storageUnavailableUntil = 0;
  let minuteStart = clock();
  let requests = 0;
  let dayStart = minuteStart;
  let events = 0;

  function quota(kind: 'request' | 'event'): boolean {
    const instant = clock();
    if (instant - minuteStart >= 60000) { minuteStart = instant; requests = 0; }
    if (instant - dayStart >= 86400000) { dayStart = instant; events = 0; }
    if (kind === 'request') return ++requests <= limits.requestsPerMinute;
    if (events >= limits.eventsPerDay) return false;
    events++;
    return true;
  }

  function ready(): boolean {
    // A disabled receiver is ready to reject events, allowing a disabled revision to roll out.
    // After transient failure, reopen admission without sending a synthetic probe or replay.
    return !stopping && (!enabled || (clock() >= storageUnavailableUntil &&
      active.size < limits.maxConcurrentRequests && inflightStorage < limits.maxConcurrentIngestions &&
      (clock() - dayStart >= 86400000 || events < limits.eventsPerDay)));
  }

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const reject = (code: Code, status: number) => { count(code); respond(response, status); };
    // Never parse, retain, log, or forward connection/identity metadata.
    request.on('error', () => {});
    response.on('error', () => {});
    if (request.rawHeaders.length / 2 > MAX_HEADER_COUNT) return reject('http_error', 431);
    if (request.method === 'GET' && (request.url === '/health/live' || request.url === '/health/ready')) {
      return respond(response, request.url === '/health/live' ? 204 : ready() ? 204 : 503);
    }
    if (!quota('request')) return reject('quota', 429);
    if (request.url !== EVENT_ROUTE) return reject('not_found', 404);
    if (request.method !== 'POST') return reject('method', 405);
    if (!enabled || stopping) return reject('disabled', 503);
    if (active.size >= limits.maxConcurrentRequests) return reject('busy', 503);
    if (request.headers['content-type']?.toLowerCase() !== 'application/json' ||
        request.headers['content-encoding'] !== undefined) return reject('unsupported', 415);
    if (request.headers['content-length'] !== undefined &&
        Number(request.headers['content-length']) > MAX_BODY_BYTES) return reject('oversized', 413);

    const controller = new AbortController();
    active.add(controller);
    const disconnect = () => { if (!response.writableFinished) controller.abort(); };
    response.once('close', disconnect);
    let storageTimer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    try {
      let value: unknown;
      const body = await readBody(request, controller.signal, limits.bodyTimeoutMs);
      try {
        value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
      } catch {
        return reject('invalid', 400);
      }
      const record = project(value, now());
      if (!record) return reject('invalid', 400);
      if (controller.signal.aborted) return reject('cancelled', 503);
      if (inflightStorage >= limits.maxConcurrentIngestions) return reject('busy', 503);
      if (!quota('event')) return reject('quota', 429);

      // Keep the work slot occupied until the adapter actually settles, even after a timeout.
      // An adapter ignoring abort must not allow an unbounded queue of replacement uploads.
      inflightStorage++;
      const upload = Promise.resolve().then(() => {
        controller.signal.throwIfAborted();
        return storage.ingest(record, controller.signal);
      }).then(
        () => { storageUnavailableUntil = 0; return 'accepted' as const; },
        () => { storageUnavailableUntil = clock() + STORAGE_RECOVERY_DELAY_MS; return 'storage_failure' as const; },
      ).finally(() => { inflightStorage--; });
      const interrupted = new Promise<'storage_timeout' | 'cancelled'>(resolve => {
        onAbort = () => resolve('cancelled');
        controller.signal.addEventListener('abort', onAbort, { once: true });
        storageTimer = setTimeout(() => {
          storageUnavailableUntil = clock() + STORAGE_RECOVERY_DELAY_MS;
          resolve('storage_timeout');
          controller.abort();
        }, limits.storageTimeoutMs);
        if (controller.signal.aborted) resolve('cancelled');
      });
      const result = await Promise.race([upload, interrupted]);
      const outcome = result === 'accepted' && controller.signal.aborted ? 'cancelled' : result;
      return reject(outcome, outcome === 'accepted' ? 204 : 503);
    } catch (error) {
      if (error instanceof BodyError) {
        return reject(error.code, error.code === 'oversized' ? 413 :
          error.code === 'body_timeout' ? 408 : error.code === 'cancelled' ? 503 : 400);
      }
      return reject('http_error', 503);
    } finally {
      clearTimeout(storageTimer);
      if (onAbort) controller.signal.removeEventListener('abort', onAbort);
      response.removeListener('close', disconnect);
      active.delete(controller);
    }
  }

  const server = createHttpServer({
    maxHeaderSize: MAX_HEADER_BYTES,
    headersTimeout: limits.headersTimeoutMs,
    requestTimeout: limits.headersTimeoutMs + limits.bodyTimeoutMs,
    connectionsCheckingInterval: Math.min(limits.headersTimeoutMs, 250),
    keepAliveTimeout: 1,
    noDelay: true,
    requireHostHeader: true,
    rejectNonStandardBodyWrites: true,
  }, (request, response) => {
    void handle(request, response).catch(() => { count('http_error'); respond(response, 503); });
  });
  server.maxHeadersCount = MAX_HEADER_COUNT + 1;
  server.maxConnections = limits.maxConnections;
  server.maxRequestsPerSocket = 1;
  // Node's automatic pipelining rejection lacks our response policy; close instead.
  server.on('dropRequest', (_request, socket) => socket.destroy());
  server.setTimeout(limits.headersTimeoutMs + limits.bodyTimeoutMs + limits.storageTimeoutMs, socket => socket.destroy());
  server.on('checkContinue', (_request, response) => { count('unsupported'); respond(response, 417); });
  server.on('checkExpectation', (_request, response) => { count('unsupported'); respond(response, 417); });
  server.on('clientError', (_error, socket) => {
    count('http_error');
    if (repliedSockets.has(socket)) { socket.destroy(); return; }
    repliedSockets.add(socket);
    if (socket.writable && !socket.writableEnded) {
      socket.end('HTTP/1.1 400 Bad Request\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    } else socket.destroy();
  });
  server.on('upgrade', (_request, socket) => socket.end(
    'HTTP/1.1 400 Bad Request\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n',
  ));
  server.on('connect', (_request, socket) => socket.end(
    'HTTP/1.1 405 Method Not Allowed\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n',
  ));
  return {
    server,
    ready,
    snapshot: () => Object.freeze({ ...counters }),
    setEnabled(value: boolean) {
      enabled = value;
      if (!value) for (const controller of active) controller.abort();
    },
    stop() {
      stopping = true;
      for (const controller of active) controller.abort();
      server.close();
      server.closeAllConnections();
    },
  };
}
