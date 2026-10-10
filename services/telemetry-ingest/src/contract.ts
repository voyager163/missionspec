import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';

export type TelemetryRecord = Readonly<Record<string, string | number | null>> & {
  readonly TimeGenerated: string;
};

export const QUEUE_MESSAGE_CODEC = 'base64-json-v1';
export const MAX_ENCODED_MESSAGE_BYTES = 1024;
export const MAX_DECODED_MESSAGE_BYTES = 1024;

export interface Storage {
  readonly readiness?: StorageReadiness;
  readonly acknowledgement?: 'queued';
  ingest(record: TelemetryRecord, signal: AbortSignal): Promise<void>;
}

export interface StorageReadiness {
  setEnabled(enabled: boolean): void;
  ready(): boolean;
  stop(): void;
}

function createEventValidator() {
  const schema = JSON.parse(readFileSync(new URL('../schema/telemetry-event.schema.json', import.meta.url), 'utf8')) as {
    properties: Record<string, unknown>;
  };
  const validate = new Ajv2020({
    strict: true,
    allErrors: false,
    coerceTypes: false,
    removeAdditional: false,
    useDefaults: false,
    ownProperties: true,
    messages: false,
  }).compile<Record<string, string | number | null>>(schema);
  return { validate, keys: Object.keys(schema.properties) };
}

export function createProjector(): (value: unknown, receipt: Date) => TelemetryRecord | undefined {
  const { validate, keys } = createEventValidator();
  return (value, receipt) => {
    if (!validate(value)) return undefined;
    const projected: Record<string, string | number | null> = {};
    for (const key of keys) projected[key] = value[key]!;
    return Object.freeze({ ...projected, TimeGenerated: receipt.toISOString() });
  };
}

/** Encode the existing projection for XML-safe Queue transport; this is not encryption. */
export function encodeQueueMessage(record: TelemetryRecord): string {
  const bytes = Buffer.from(JSON.stringify(record), 'utf8');
  const encoded = bytes.toString('base64');
  if (bytes.byteLength > MAX_DECODED_MESSAGE_BYTES || Buffer.byteLength(encoded, 'utf8') > MAX_ENCODED_MESSAGE_BYTES) {
    throw new Error('QUEUE_RECORD_INVALID');
  }
  return encoded;
}

/** Decode only canonical Base64, then validate without generating a new receipt time or fields. */
export function createQueuedRecordValidator(): (text: string) => TelemetryRecord | undefined {
  const { validate } = createEventValidator();
  return text => {
    if (typeof text !== 'string' || !text || Buffer.byteLength(text, 'utf8') > MAX_ENCODED_MESSAGE_BYTES ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) return undefined;
    try {
      const decoded = Buffer.from(text, 'base64');
      if (decoded.byteLength > MAX_DECODED_MESSAGE_BYTES || decoded.toString('base64') !== text) return undefined;
      // Preserve a BOM so JSON.parse rejects it instead of silently accepting a different byte stream.
      const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(decoded));
      if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
      const { TimeGenerated, ...event } = value as Record<string, unknown>;
      if (typeof TimeGenerated !== 'string' || new Date(TimeGenerated).toISOString() !== TimeGenerated ||
          !validate(event)) return undefined;
      return Object.freeze({ ...event, TimeGenerated });
    } catch { return undefined; }
  };
}
