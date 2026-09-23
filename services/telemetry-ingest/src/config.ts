import { limitRanges, validateLimits } from './server.js';
import type { Limits } from './server.js';

export const STREAM_NAME = 'Custom-MissionSpecTelemetry';

export class ConfigError extends Error {
  constructor(readonly code: 'CONFIG_MISSING' | 'CONFIG_INVALID' | 'CONFIG_UNSAFE_ENVIRONMENT' | 'CONFIG_UNSAFE_RUNTIME') {
    super(code);
  }
}

export interface AzureConfig {
  endpoint: string;
  ruleId: string;
  ruleResourceId: string;
  clientId: string;
}

export interface OperatorConfig {
  host: '0.0.0.0' | '127.0.0.1';
  port: number;
  enabled: boolean;
  limits: Limits;
  azure: AzureConfig;
}

export const limitEnvironment: Readonly<Record<keyof Limits, string>> = {
  bodyTimeoutMs: 'MSR_BODY_TIMEOUT_MS',
  storageTimeoutMs: 'MSR_STORAGE_TIMEOUT_MS',
  headersTimeoutMs: 'MSR_HEADERS_TIMEOUT_MS',
  maxConnections: 'MSR_MAX_CONNECTIONS',
  maxConcurrentRequests: 'MSR_MAX_CONCURRENT_REQUESTS',
  maxConcurrentIngestions: 'MSR_MAX_CONCURRENT_INGESTIONS',
  requestsPerMinute: 'MSR_REQUESTS_PER_MINUTE',
  eventsPerDay: 'MSR_EVENTS_PER_DAY',
};

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validateRuntimeArguments(argumentsValue: readonly string[]): void {
  if (argumentsValue.some(argument => /^--(?:inspect|debug|experimental-(?:network|storage|worker|inspector)-inspection|experimental-inspector-network-resource)/u.test(argument))) {
    throw new ConfigError('CONFIG_UNSAFE_RUNTIME');
  }
}

export function parseConfig(environment: Readonly<Record<string, string | undefined>>): OperatorConfig {
  for (const [key, value] of Object.entries(environment)) {
    if (value && (/^(APPLICATIONINSIGHTS|APPINSIGHTS|OTEL_)/i.test(key) ||
      /^(AZURE_LOG_LEVEL|AZURE_AUTHORITY_HOST|NODE_OPTIONS|NODE_DEBUG|NODE_DEBUG_NATIVE|NODE_TLS_REJECT_UNAUTHORIZED|NODE_EXTRA_CA_CERTS|DEBUG|HTTPS?_PROXY|ALL_PROXY)$/i.test(key))) {
      throw new ConfigError('CONFIG_UNSAFE_ENVIRONMENT');
    }
  }
  const required = (name: string): string => {
    const value = environment[name];
    if (!value) throw new ConfigError('CONFIG_MISSING');
    return value;
  };
  const integer = (name: string, min: number, max: number) => {
    const text = required(name);
    if (!/^[0-9]+$/.test(text)) throw new ConfigError('CONFIG_INVALID');
    const value = Number(text);
    if (!Number.isSafeInteger(value) || value < min || value > max) throw new ConfigError('CONFIG_INVALID');
    return value;
  };
  const host = required('MSR_BIND_HOST');
  const enabled = required('MSR_INGESTION_ENABLED');
  if ((host !== '0.0.0.0' && host !== '127.0.0.1') || !['true', 'false'].includes(enabled)) {
    throw new ConfigError('CONFIG_INVALID');
  }
  const subscription = required('AZURE_SUBSCRIPTION_ID');
  const tenant = required('AZURE_TENANT_ID');
  const clientId = required('AZURE_CLIENT_ID');
  const group = required('MSR_RESOURCE_GROUP');
  if (![subscription, tenant, clientId].every(value => uuid.test(value)) || !/^[a-zA-Z0-9_-]{1,90}$/.test(group)) {
    throw new ConfigError('CONFIG_INVALID');
  }
  const ruleResourceId = required('AZURE_DCR_RESOURCE_ID');
  const expectedPrefix = `/subscriptions/${subscription}/resourceGroups/${group}/providers/Microsoft.Insights/dataCollectionRules/`;
  if (!ruleResourceId.toLowerCase().startsWith(expectedPrefix.toLowerCase()) ||
      !/^[a-zA-Z0-9_-]{1,64}$/.test(ruleResourceId.slice(expectedPrefix.length))) {
    throw new ConfigError('CONFIG_INVALID');
  }
  const ruleId = required('AZURE_DCR_IMMUTABLE_ID');
  if (!/^dcr-[0-9a-f]{32}$/.test(ruleId)) throw new ConfigError('CONFIG_INVALID');
  let endpoint: URL;
  try { endpoint = new URL(required('AZURE_LOGS_ENDPOINT')); } catch (error) {
    if (error instanceof ConfigError) throw error;
    throw new ConfigError('CONFIG_INVALID');
  }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.port ||
      endpoint.search || endpoint.hash || endpoint.pathname !== '/' ||
      !/^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.ingest\.monitor\.azure\.com$/.test(endpoint.hostname)) {
    throw new ConfigError('CONFIG_INVALID');
  }
  const limits = Object.fromEntries(Object.entries(limitEnvironment).map(([key, name]) => {
    const [min, max] = limitRanges[key as keyof Limits];
    return [key, integer(name, min, max)];
  })) as unknown as Limits;
  try { validateLimits(limits); } catch { throw new ConfigError('CONFIG_INVALID'); }
  return {
    host, enabled: enabled === 'true', port: integer('PORT', 1024, 65535), limits,
    azure: { endpoint: endpoint.origin, ruleId, ruleResourceId, clientId },
  };
}
