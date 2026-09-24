import type { LogsIngestionClientOptions } from '@azure/monitor-ingestion';
import type { Debugger } from '@azure/logger';
import type { AzureConfig } from './config.js';
import { STREAM_NAME } from './config.js';
import type { Storage, StorageReadiness, TelemetryRecord } from './contract.js';
import { createIdentityReadiness } from './identity-readiness.js';

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
  const [{ ManagedIdentityCredential }, { LogsIngestionClient }] = await Promise.all([
    import('@azure/identity'),
    import('@azure/monitor-ingestion'),
  ]);
  const identity = new ManagedIdentityCredential({
    clientId: config.clientId,
    retryOptions: { maxRetries: 0 },
    loggingOptions: { logger: noLog },
  });
  const { credential, readiness } = createIdentityReadiness(identity);
  const client = new LogsIngestionClient(config.endpoint, credential, azureClientOptions);
  client.pipeline.removePolicy({ name: 'logPolicy' });
  client.pipeline.removePolicy({ name: 'tracingPolicy' });
  return createStorageAdapter(client, config.ruleId, readiness);
}
