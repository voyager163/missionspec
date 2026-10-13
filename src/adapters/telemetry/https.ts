import { request } from 'node:https';
import type { RequestOptions } from 'node:https';
import type { ClientRequest, IncomingMessage } from 'node:http';
import { MAX_EVENT_BYTES, serializeTelemetryEvent } from '../../observability/events.js';
import { validEndpoint } from '../../observability/client.js';
import type { TelemetryTransport } from '../../observability/client.js';

/** Constructing this adapter neither opens a connection nor looks up an endpoint. */
export function createHttpsTelemetryTransport(
  requestHttps: (url: string, options: RequestOptions, callback: (response: IncomingMessage) => void) => ClientRequest = request,
): TelemetryTransport {
  return Object.freeze({
    async send(input: Parameters<TelemetryTransport['send']>[0]): Promise<{ readonly state: 'delivered' | 'unavailable' }> {
      try {
        if (!validEndpoint(input.endpoint) || input.signal.aborted ||
          typeof input.body !== 'string' || Buffer.byteLength(input.body) > MAX_EVENT_BYTES) {
          return { state: 'unavailable' };
        }
        if (serializeTelemetryEvent(JSON.parse(input.body) as unknown) !== input.body) return { state: 'unavailable' };
      } catch {
        return { state: 'unavailable' };
      }
      return new Promise((resolve) => {
        let done = false;
        let timer: ReturnType<typeof setTimeout> | undefined;
        let req: ClientRequest | undefined;
        const finish = (state: 'delivered' | 'unavailable'): void => {
          if (done) return;
          done = true;
          if (timer !== undefined) clearTimeout(timer);
          resolve({ state });
        };
        try {
          req = requestHttps(input.endpoint, {
            method: 'POST',
            agent: false,
            signal: input.signal,
            maxHeaderSize: 4096,
            headers: {
              'content-type': 'application/json',
              'content-length': Buffer.byteLength(input.body),
              connection: 'close',
            },
          }, (res) => {
            const accepted = res.statusCode !== undefined && res.statusCode >= 200 && res.statusCode < 300;
            // A status-only protocol needs no body: destroy rather than buffering or draining unbounded data.
            res.on('error', () => {});
            res.destroy();
            finish(accepted ? 'delivered' : 'unavailable');
          });
          req.on('error', () => { finish('unavailable'); });
          timer = setTimeout(() => {
            finish('unavailable');
            req?.destroy();
          }, 1000);
          req.end(input.body);
        } catch {
          finish('unavailable');
          req?.destroy();
        }
      });
    },
  });
}
