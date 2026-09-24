import type { LogsIngestionClientOptions } from '@azure/monitor-ingestion';
import type { StoragePipelineOptions } from '@azure/storage-queue';
import type { Debugger } from '@azure/logger';
import type { AzureConfig } from './config.js';
import { STREAM_NAME } from './config.js';
import type { Storage, StorageReadiness, TelemetryRecord } from './contract.js';
import { createIdentityReadiness, INGESTION_SCOPE, STORAGE_SCOPE } from './identity-readiness.js';
import { createQueueStorage } from './queue-storage.js';

export interface UploadClient {
  upload(ruleId: string, streamName: string, records: Record<string, unknown>[], options: {
    abortSignal: AbortSignal;
    maxConcurrency: number;
  }): Promise<void>;
}

const noLog: Debugger = Object.assign(() => {}, {
  enabled: false,
  namespace: 'missionspec:silent',
  destroy: () => true,
  log: () => {},
  extend: () => noLog,
});

export const azureClientOptions: LogsIngestionClientOptions = {
  retryOptions: { maxRetries: 0 },
  redirectOptions: { maxRetries: 0 },
  loggingOptions: { logger: noLog },
  audience: 'https://monitor.azure.com',
};

// The pinned queue SDK passes these options into Core's pipeline; the wire tests enforce no redirects.
export const queueClientOptions: StoragePipelineOptions & Pick<LogsIngestionClientOptions, 'redirectOptions'> = {
  retryOptions: { maxTries: 1, tryTimeoutInMs: 5000 },
  redirectOptions: { maxRetries: 0 },
  audience: STORAGE_SCOPE,
};

/** The client is injected so all behavior can be exercised without Azure credentials. */
export function createStorageAdapter(client: UploadClient, ruleId: string, readiness?: StorageReadiness): Storage {
  return {
    ...(readiness ? { readiness } : {}),
    async ingest(record: TelemetryRecord, signal: AbortSignal): Promise<void> {
      signal.throwIfAborted();
      if (readiness && !readiness.ready()) throw new Error('IDENTITY_NOT_READY');
      await client.upload(ruleId, STREAM_NAME, [{ ...record }], { abortSignal: signal, maxConcurrency: 1 });
      signal.throwIfAborted();
    },
  };
}

export async function createAzureStorage(config: AzureConfig): Promise<Storage> {
  const { AzureLogger, setLogLevel } = await import('@azure/logger');
  setLogLevel(undefined);
  AzureLogger.log = () => {};
  const [{ ManagedIdentityCredential }, { LogsIngestionClient }, { QueueClient }] = await Promise.all([
    import('@azure/identity'),
    import('@azure/monitor-ingestion'),
    import('@azure/storage-queue'),
  ]);
  const identity = () => new ManagedIdentityCredential({
    clientId: config.clientId,
    retryOptions: { maxRetries: 0 },
    loggingOptions: { logger: noLog },
  });
  const producer = createIdentityReadiness(identity(), STORAGE_SCOPE);
  const consumer = createIdentityReadiness(identity(), INGESTION_SCOPE);
  const client = new LogsIngestionClient(config.endpoint, consumer.credential, azureClientOptions);
  client.pipeline.removePolicy({ name: 'logPolicy' });
  client.pipeline.removePolicy({ name: 'tracingPolicy' });
  const queue = new QueueClient(config.queueUrl, producer.credential, queueClientOptions);
  return createQueueStorage({
    queue, upload: client, ruleId: config.ruleId,
    producerIdentity: producer.readiness, consumerIdentity: consumer.readiness,
  });
}
