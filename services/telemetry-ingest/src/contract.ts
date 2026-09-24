import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';

export type TelemetryRecord = Readonly<Record<string, string | number | null>> & {
  readonly TimeGenerated: string;
};

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

/** Validate the persisted projection without generating a new receipt time or analytics fields. */
export function createQueuedRecordValidator(): (text: string) => TelemetryRecord | undefined {
  const { validate } = createEventValidator();
  return text => {
    if (Buffer.byteLength(text, 'utf8') > 1024) return undefined;
    try {
      const value: unknown = JSON.parse(text);
      if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
      const { TimeGenerated, ...event } = value as Record<string, unknown>;
      if (typeof TimeGenerated !== 'string' || new Date(TimeGenerated).toISOString() !== TimeGenerated ||
          !validate(event)) return undefined;
      return Object.freeze({ ...event, TimeGenerated });
    } catch { return undefined; }
  };
}
