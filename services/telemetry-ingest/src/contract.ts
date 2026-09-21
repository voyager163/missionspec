import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';

export type TelemetryRecord = Readonly<Record<string, string | number | null>> & {
  readonly TimeGenerated: string;
};

export interface Storage {
  ingest(record: TelemetryRecord, signal: AbortSignal): Promise<void>;
}

export function createProjector(): (value: unknown, receipt: Date) => TelemetryRecord | undefined {
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
  const keys = Object.keys(schema.properties);
  return (value, receipt) => {
    if (!validate(value)) return undefined;
    const projected: Record<string, string | number | null> = {};
    for (const key of keys) projected[key] = value[key]!;
    return Object.freeze({ ...projected, TimeGenerated: receipt.toISOString() });
  };
}
