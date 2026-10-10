import type { QueueClient, DequeuedMessageItem } from '@azure/storage-queue';
import type { UploadClient } from './azure-storage.js';
import { STREAM_NAME } from './config.js';
import { createQueuedRecordValidator, encodeQueueMessage } from './contract.js';
import type { Storage, StorageReadiness, TelemetryRecord } from './contract.js';

export const QUEUE_TTL_SECONDS = 3600;
export const QUEUE_CAPACITY = 10000;
export const QUEUE_MAX_ENQUEUES = 8;
export const QUEUE_BATCH_SIZE = 32;
export const QUEUE_VISIBILITY_SECONDS = 60;
export const QUEUE_MAX_DELIVERIES = 3;
export const QUEUE_ENQUEUE_TIMEOUT_MS = 650;
export const QUEUE_TRANSACTION_TIMEOUT_MS = 5000;
export const QUEUE_PROPERTIES_INTERVAL_MS = 30000;
export const QUEUE_IDLE_POLL_MS = 30000;
export const WORKER_UPLOAD_TIMEOUT_MS = 15000;
export const WORKER_BATCH_TIMEOUT_MS = 45000;
export const QUEUE_BACKOFF_MS = 5000;
export const QUEUE_MAX_BACKOFF_MS = 60000;

type Queue = Pick<QueueClient, 'getProperties' | 'sendMessage' | 'receiveMessages' | 'deleteMessage'>;
type Code = 'queued' | 'logs_delivered' | 'queue_send_unknown' | 'queue_properties_failed' |
  'queue_receive_unknown' | 'queue_delete_unknown' | 'logs_upload_unknown' |
  'dropped_invalid' | 'dropped_expired' | 'dropped_attempts';

export interface QueueStorageOptions {
  queue: Queue;
  upload: UploadClient;
  ruleId: string;
  producerIdentity: StorageReadiness;
  consumerIdentity: StorageReadiness;
  now?: () => number;
  monotonicNow?: () => number;
}

/** An inert durable producer and one leased-batch consumer; never a memory queue or direct fallback. */
export function createQueueStorage(options: QueueStorageOptions): Storage & {
  snapshot(): Readonly<Partial<Record<Code, number>>>;
} {
  const { queue, upload, ruleId, producerIdentity, consumerIdentity } = options;
  const now = options.now ?? Date.now;
  const clock = options.monotonicNow ?? (() => performance.now());
  const validate = createQueuedRecordValidator();
  const counters: Partial<Record<Code, number>> = {};
  const count = (code: Code, amount = 1) => { counters[code] = Math.min((counters[code] ?? 0) + amount, Number.MAX_SAFE_INTEGER); };
  const active = new Set<AbortController>();
  let enabled = false, stopped = false, propertiesRunning = false, workerRunning = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let observedAt = -Infinity, estimatedCount = QUEUE_CAPACITY, admissions = 0, enqueues = 0;
  let propertiesDue = 0, workerDue = 0, queueUnavailableUntil = 0;
  let queueFailures = 0, uploadFailures = 0;
  const running = () => enabled && !stopped;
  const backoff = (failures: number) => Math.min(QUEUE_MAX_BACKOFF_MS, QUEUE_BACKOFF_MS * 2 ** Math.min(failures, 4));
  const queueFailed = (code: Code) => {
    count(code);
    observedAt = -Infinity;
    queueUnavailableUntil = clock() + backoff(queueFailures++);
    propertiesDue = queueUnavailableUntil;
  };
  const queueConnected = () => running() && producerIdentity.ready() &&
    clock() < observedAt + QUEUE_PROPERTIES_INTERVAL_MS && clock() >= queueUnavailableUntil;

  async function perform<T>(
    operation: (signal: AbortSignal) => Promise<T>, budget: number, failure: () => void, parent?: AbortSignal,
  ): Promise<T> {
    if (!running() || parent?.aborted || budget <= 0) throw new Error('QUEUE_NOT_READY');
    const controller = new AbortController();
    const deadline = clock() + budget;
    let failed = false;
    const uncertain = () => { if (!failed) { failed = true; failure(); } };
    const abort = () => { uncertain(); controller.abort(); };
    active.add(controller);
    parent?.addEventListener('abort', abort, { once: true });
    controller.signal.addEventListener('abort', uncertain, { once: true });
    const timeout = setTimeout(abort, budget);
    try {
      controller.signal.throwIfAborted();
      const result = await operation(controller.signal);
      // Keep the slot until actual SDK settlement; no replacement work after an ignored abort.
      if (controller.signal.aborted || !running() || clock() >= deadline) throw new Error('QUEUE_OUTCOME_UNKNOWN');
      return result;
    } catch {
      uncertain();
      throw new Error('QUEUE_OUTCOME_UNKNOWN');
    } finally {
      clearTimeout(timeout);
      parent?.removeEventListener('abort', abort);
      active.delete(controller);
    }
  }

  async function refreshProperties(): Promise<void> {
    propertiesRunning = true;
    const startAdmissions = admissions;
    try {
      const approximateCount = await perform(async signal => {
        const response = await queue.getProperties({ abortSignal: signal });
        const value = response?.approximateMessagesCount;
        if (response?._response?.status !== 200 || typeof value !== 'number' ||
            !Number.isSafeInteger(value) || value < 0) throw new Error('QUEUE_PROPERTIES_INVALID');
        return value;
      }, QUEUE_TRANSACTION_TIMEOUT_MS, () => queueFailed('queue_properties_failed'));
      // This is conservative only locally. Remote approximate counts and other replicas are not atomic.
      estimatedCount = approximateCount + admissions - startAdmissions + enqueues;
      observedAt = clock();
      propertiesDue = observedAt + QUEUE_PROPERTIES_INTERVAL_MS;
      queueFailures = 0;
    } catch {
      if (clock() >= queueUnavailableUntil) queueFailed('queue_properties_failed');
    } finally {
      propertiesRunning = false;
    }
  }

  function expired(message: DequeuedMessageItem, record: TelemetryRecord): boolean {
    return message.expiresOn.getTime() <= now() ||
      Date.parse(record.TimeGenerated) + QUEUE_TTL_SECONDS * 1000 <= now();
  }
  function validEnvelope(message: DequeuedMessageItem): boolean {
    return !!message && typeof message.messageId === 'string' && message.messageId.length > 0 && message.messageId.length <= 128 &&
      typeof message.popReceipt === 'string' && message.popReceipt.length > 0 && message.popReceipt.length <= 1024 &&
      Number.isSafeInteger(message.dequeueCount) && message.dequeueCount >= 1 &&
      message.insertedOn instanceof Date && message.expiresOn instanceof Date &&
      Number.isFinite(message.insertedOn.getTime()) && Number.isFinite(message.expiresOn.getTime());
  }

  async function consume(): Promise<void> {
    workerRunning = true;
    const batchDeadline = clock() + WORKER_BATCH_TIMEOUT_MS;
    const remaining = (limit: number) => Math.min(limit, batchDeadline - clock());
    try {
      const messages = await perform(async signal => {
        const response = await queue.receiveMessages({
          numberOfMessages: QUEUE_BATCH_SIZE, visibilityTimeout: QUEUE_VISIBILITY_SECONDS, abortSignal: signal,
        });
        const items = response?.receivedMessageItems;
        if (response?._response?.status !== 200 || !Array.isArray(items) || items.length > QUEUE_BATCH_SIZE ||
            items.some(message => !validEnvelope(message))) throw new Error('QUEUE_RECEIVE_INVALID');
        return items;
      }, QUEUE_TRANSACTION_TIMEOUT_MS, () => queueFailed('queue_receive_unknown'));
      const deliver: { message: DequeuedMessageItem; record: TelemetryRecord }[] = [];
      const discard: { message: DequeuedMessageItem; code: 'dropped_invalid' | 'dropped_expired' | 'dropped_attempts' }[] = [];
      for (const message of messages) {
        const record = typeof message.messageText === 'string' ? validate(message.messageText) : undefined;
        if (!record || Date.parse(record.TimeGenerated) > now() ||
            message.expiresOn.getTime() > message.insertedOn.getTime() + (QUEUE_TTL_SECONDS + 1) * 1000) {
          discard.push({ message, code: 'dropped_invalid' });
        } else if (expired(message, record)) discard.push({ message, code: 'dropped_expired' });
        else if (message.dequeueCount > QUEUE_MAX_DELIVERIES) discard.push({ message, code: 'dropped_attempts' });
        else deliver.push({ message, record });
      }
      // Never wait for Monitor credential initialization while holding a newly acquired lease.
      if (!running() || !producerIdentity.ready() || (deliver.length && !consumerIdentity.ready())) return;
      if (deliver.length) {
        const ttlRemaining = Math.min(...deliver.map(({ message, record }) => Math.min(
          message.expiresOn.getTime(), Date.parse(record.TimeGenerated) + QUEUE_TTL_SECONDS * 1000,
        ) - now()));
        await perform(async signal => {
          await upload.upload(ruleId, STREAM_NAME, deliver.map(value => ({ ...value.record })),
            { abortSignal: signal, maxConcurrency: 1 });
        }, Math.min(remaining(WORKER_UPLOAD_TIMEOUT_MS), ttlRemaining), () => {
          count('logs_upload_unknown');
          workerDue = clock() + backoff(uploadFailures++);
        });
        count('logs_delivered', deliver.length);
        uploadFailures = 0;
      }
      // Only confirmed delivery or explicit invalid/expired/exhausted disposition permits deletion.
      // A failed/uncertain delete ends this batch; no tight deletion retry or visibility renewal.
      for (const { message, code } of [
        ...deliver.map(value => ({ message: value.message, code: undefined })),
        ...discard,
      ]) {
        if (!running() || !producerIdentity.ready() || remaining(QUEUE_TRANSACTION_TIMEOUT_MS) <= 0) return;
        await perform(async signal => {
          const response = await queue.deleteMessage(message.messageId, message.popReceipt, { abortSignal: signal });
          if (response?._response?.status !== 204) throw new Error('QUEUE_DELETE_INVALID');
        }, remaining(QUEUE_TRANSACTION_TIMEOUT_MS), () => queueFailed('queue_delete_unknown'));
        if (code) count(code);
      }
      workerDue = clock() + (messages.length ? 1000 : QUEUE_IDLE_POLL_MS);
    } catch {
      // perform recorded the static uncertainty class. The lease/TTL, not a resend here, governs recovery.
    } finally {
      workerRunning = false;
      workerDue = Math.max(workerDue, clock() + 1000);
    }
  }

  function schedule(): void {
    if (!running() || timer) return;
    timer = setTimeout(tick, 1000);
    timer.unref();
  }
  function tick(): void {
    timer = undefined;
    if (!running()) return;
    if (producerIdentity.ready() && !propertiesRunning && clock() >= propertiesDue) void refreshProperties();
    if (queueConnected() && consumerIdentity.ready() && !workerRunning && clock() >= workerDue) void consume();
    schedule();
  }
  const readiness: StorageReadiness = {
    setEnabled(value) {
      if (stopped) return;
      enabled = value;
      producerIdentity.setEnabled(value);
      consumerIdentity.setEnabled(value);
      if (value) schedule();
      else {
        clearTimeout(timer);
        timer = undefined;
        observedAt = -Infinity;
        for (const controller of active) controller.abort();
      }
    },
    ready: () => queueConnected() && estimatedCount < QUEUE_CAPACITY && enqueues < QUEUE_MAX_ENQUEUES,
    stop() {
      readiness.setEnabled(false);
      stopped = true;
      producerIdentity.stop();
      consumerIdentity.stop();
    },
  };
  return {
    acknowledgement: 'queued',
    readiness,
    snapshot: () => Object.freeze({ ...counters }),
    async ingest(record, signal) {
      signal.throwIfAborted();
      const message = encodeQueueMessage(record);
      if (!validate(message)) throw new Error('QUEUE_RECORD_INVALID');
      if (!readiness.ready()) throw new Error('QUEUE_NOT_READY');
      enqueues++;
      admissions++;
      estimatedCount++;
      try {
        await perform(async abortSignal => {
          const response = await queue.sendMessage(message, {
            messageTimeToLive: QUEUE_TTL_SECONDS, visibilityTimeout: 0, abortSignal,
          });
          if (response?._response?.status !== 201 || typeof response.messageId !== 'string' || !response.messageId ||
              typeof response.popReceipt !== 'string' || !response.popReceipt) throw new Error('QUEUE_ACK_INVALID');
        }, QUEUE_ENQUEUE_TIMEOUT_MS, () => queueFailed('queue_send_unknown'), signal);
        count('queued');
        // One new durable message can wake the worker; the timer itself never stores event payloads.
        workerDue = Math.min(workerDue, clock());
      } finally {
        enqueues--;
      }
    },
  };
}
