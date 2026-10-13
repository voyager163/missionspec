import { digestContent, type ContentDigest } from '../../kernel/revisions.js';
import { NativeBridgeError, NATIVE_PROPOSAL_PINS } from './contracts.js';

export type CodexSubscriptionMetadataMethod = 'account/read' | 'account/rateLimits/read' | 'model/list';

/** An already initialized, bounded transport. It must deny server requests and never create a thread. */
export interface CodexSubscriptionMetadataReader {
  request(method: CodexSubscriptionMetadataMethod, params: Readonly<Record<string, unknown>>): Promise<unknown>;
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new NativeBridgeError('invalid-input', 'Malformed Codex subscription metadata.');
  }
  return value as Record<string, unknown>;
}

function text(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || /[\u0000-\u001f]/u.test(value)) {
    throw new NativeBridgeError('invalid-input', 'Malformed Codex metadata identity.');
  }
  return value;
}

function optionalBoolean(value: unknown): boolean | null {
  if (value == null) return null;
  if (typeof value !== 'boolean') throw new NativeBridgeError('invalid-input', 'Malformed Codex usage state.');
  return value;
}

function usedPercent(value: unknown): number | null {
  if (value == null) return null;
  const percent = object(value).usedPercent;
  if (typeof percent !== 'number' || !Number.isSafeInteger(percent) || percent < 0) {
    throw new NativeBridgeError('invalid-input', 'Malformed Codex usage window.');
  }
  return percent;
}

function accountSnapshot(value: unknown) {
  const response = object(value);
  if (response.requiresOpenaiAuth !== true) throw new NativeBridgeError('scope-exceeded', 'Codex did not select the first-party authenticated provider.');
  if (response.account == null) return { type: 'signed-out', planType: null, identityDigest: null } as const;
  const account = object(response.account);
  if (account.type !== 'chatgpt') {
    if (!['apiKey', 'amazonBedrock'].includes(String(account.type))) throw new NativeBridgeError('invalid-input', 'Unknown Codex authentication type.');
    return { type: 'non-subscription', planType: null, identityDigest: null } as const;
  }
  const planType = text(account.planType);
  if (!['free', 'go', 'plus', 'pro', 'prolite', 'team', 'self_serve_business_prolite',
    'self_serve_business_usage_based', 'business', 'ent26', 'enterprise_cbp_automation',
    'enterprise_cbp_usage_based', 'enterprise', 'edu', 'edu_plus', 'edu_pro', 'unknown'].includes(planType)) {
    throw new NativeBridgeError('invalid-input', 'Unknown Codex subscription plan metadata.');
  }
  const email = account.email == null ? null : text(account.email);
  return { type: 'chatgpt', planType, identityDigest: email === null ? null : digestContent(email.trim().toLowerCase()) } as const;
}

function quotaSnapshot(value: unknown) {
  const snapshot = object(value);
  const credits = snapshot.credits == null ? null : object(snapshot.credits);
  if (credits !== null && (typeof credits.hasCredits !== 'boolean' || typeof credits.unlimited !== 'boolean')) {
    throw new NativeBridgeError('invalid-input', 'Malformed Codex credit metadata.');
  }
  return {
    limitId: snapshot.limitId == null ? null : text(snapshot.limitId),
    primaryUsedPercent: usedPercent(snapshot.primary), secondaryUsedPercent: usedPercent(snapshot.secondary),
    hasPaidCredits: credits === null ? null : optionalBoolean(credits.hasCredits),
    unlimitedCredits: credits === null ? null : optionalBoolean(credits.unlimited),
    spendControlReached: optionalBoolean(snapshot.spendControlReached),
  };
}

async function read(reader: CodexSubscriptionMetadataReader, method: CodexSubscriptionMetadataMethod, params: Readonly<Record<string, unknown>>) {
  try {
    return await reader.request(method, params);
  } catch {
    throw new NativeBridgeError('capability-unavailable', `Codex ${method} metadata read failed; no pilot was admitted.`);
  }
}

/**
 * Subscription-native skills/CLI/MCP preflight, not the API-key proposal bridge.
 * Quota availability never proves that later work cannot consume purchased credits.
 */
export async function inspectCodexSubscription(
  reader: CodexSubscriptionMetadataReader,
  configuredDefaultModel: string | null,
  confirmedAccountDigest?: ContentDigest,
) {
  if (configuredDefaultModel !== null) text(configuredDefaultModel);
  const account = accountSnapshot(await read(reader, 'account/read', { refreshToken: false }));
  const boundary = {
    host: 'codex', scope: 'subscription-native-metadata-only', reviewedCliVersion: NATIVE_PROPOSAL_PINS.codex.cli,
    modelCalls: 0, pilotAdmission: 'required', noAdditionalChargeProtection: 'unverified',
  } as const;
  if (account.type !== 'chatgpt') {
    return { ...boundary, observedAt: new Date().toISOString(), account, model: null, ordinaryUsageAllowed: null, quotas: [], blockers: ['personal-subscription-login-required'] };
  }
  if (confirmedAccountDigest !== undefined && account.identityDigest === null) {
    throw new NativeBridgeError('capability-unavailable', 'Codex omitted the identity needed to bind this read to the confirmed account.');
  }
  if (confirmedAccountDigest !== undefined && account.identityDigest !== confirmedAccountDigest) {
    throw new NativeBridgeError('scope-exceeded', 'Codex selected a different account from the confirmed binding.');
  }

  const models: { id: string; model: string; isDefault: boolean; multiAgentVersion: string | null }[] = [];
  const ids = new Set<string>();
  const cursors = new Set<string>();
  let cursor: string | null = null;
  for (let page = 0; page < 3; page++) {
    const response = object(await read(reader, 'model/list', { cursor, limit: 50, includeHidden: false }));
    if (!Array.isArray(response.data) || response.data.length > 50) throw new NativeBridgeError('limit-reached', 'Codex model metadata exceeds its page limit.');
    for (const entry of response.data) {
      const model = object(entry);
      const id = text(model.id);
      if (ids.has(id) || typeof model.isDefault !== 'boolean') throw new NativeBridgeError('invalid-input', 'Ambiguous Codex model metadata.');
      if (model.multiAgentVersion != null && !['disabled', 'v1', 'v2'].includes(String(model.multiAgentVersion))) {
        throw new NativeBridgeError('invalid-input', 'Unknown Codex multi-agent metadata.');
      }
      ids.add(id);
      models.push({
        id, model: text(model.model), isDefault: model.isDefault,
        multiAgentVersion: model.multiAgentVersion == null ? null : text(model.multiAgentVersion),
      });
    }
    if (response.nextCursor == null) { cursor = null; break; }
    cursor = text(response.nextCursor);
    if (cursors.has(cursor)) throw new NativeBridgeError('invalid-input', 'Codex repeated a model metadata cursor.');
    cursors.add(cursor);
  }
  if (cursor !== null) throw new NativeBridgeError('limit-reached', 'Codex model metadata exceeds its total page limit.');
  const matches = models.filter((model) => configuredDefaultModel === null ? model.isDefault : model.model === configuredDefaultModel);
  if (matches.length > 1) throw new NativeBridgeError('invalid-input', 'Codex disclosed an ambiguous default model.');
  const model = matches[0] ?? null;

  const usage = object(await read(reader, 'account/rateLimits/read', {
    excludeResetCreditDetails: true, supportsLunaReserve: false,
  }));
  const ordinaryUsageAllowed = optionalBoolean(usage.ordinaryUsageAllowed);
  object(usage.rateLimits);
  const buckets = usage.rateLimitsByLimitId == null ? [usage.rateLimits] : Object.values(object(usage.rateLimitsByLimitId));
  if (buckets.length === 0 || buckets.length > 32) throw new NativeBridgeError('invalid-input', 'Codex disclosed an invalid number of usage buckets.');
  const quotas = buckets.map(quotaSnapshot);
  const after = accountSnapshot(await read(reader, 'account/read', { refreshToken: false }));
  if (JSON.stringify(account) !== JSON.stringify(after)) throw new NativeBridgeError('scope-exceeded', 'Codex account changed during metadata inspection.');

  const blockers = ['billing-controls-review-required', 'central-pilot-admission-required'];
  if (confirmedAccountDigest === undefined) blockers.unshift('personal-account-confirmation-required');
  if (account.identityDigest === null) blockers.push('account-identity-unavailable');
  if (model === null) blockers.push('configured-default-model-unavailable');
  if (ordinaryUsageAllowed !== true) blockers.push('included-usage-not-confirmed');
  if (quotas.some((quota) => quota.hasPaidCredits !== false || quota.unlimitedCredits !== false)) {
    blockers.push('paid-credit-fallback-present-or-unknown');
  }
  if (quotas.some((quota) => quota.spendControlReached === true)) blockers.push('spend-control-reached');
  return { ...boundary, observedAt: new Date().toISOString(), account, model, ordinaryUsageAllowed, quotas, blockers };
}
