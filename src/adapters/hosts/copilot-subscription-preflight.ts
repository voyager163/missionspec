import { digestContent, type ContentDigest } from '../../kernel/revisions.js';
import { NativeBridgeError, NATIVE_PROPOSAL_PINS } from './contracts.js';

export type CopilotSubscriptionMetadataMethod =
  'status.get' | 'auth.getStatus' | 'account.getQuota' | 'models.list' | 'user.settings.get';

/** A connected, bounded metadata transport with stored-user auth and no session allocation. */
export interface CopilotSubscriptionMetadataReader {
  request(method: CopilotSubscriptionMetadataMethod, params: Readonly<Record<string, unknown>>): Promise<unknown>;
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new NativeBridgeError('invalid-input', 'Malformed Copilot subscription metadata.');
  }
  return value as Record<string, unknown>;
}

function modelId(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$/u.test(value)) {
    throw new NativeBridgeError('invalid-input', 'Malformed Copilot model metadata.');
  }
  return value;
}

function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new NativeBridgeError('invalid-input', 'Copilot omitted a required quota or settings state.');
  return value;
}

function amount(value: unknown, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > Number.MAX_SAFE_INTEGER) {
    throw new NativeBridgeError('invalid-input', 'Malformed Copilot entitlement amount.');
  }
  return value;
}

function accountSnapshot(value: unknown) {
  const auth = object(value);
  if (auth.isAuthenticated !== true) throw new NativeBridgeError('authority-required', 'Copilot stored-user authentication is unavailable.');
  if (auth.authType !== 'user' || !['github.com', 'https://github.com'].includes(String(auth.host))) {
    throw new NativeBridgeError('scope-exceeded', 'Copilot did not select the stored personal GitHub authentication route.');
  }
  if (typeof auth.login !== 'string' || !/^[a-zA-Z0-9-]{1,39}$/u.test(auth.login)) {
    throw new NativeBridgeError('invalid-input', 'Copilot omitted a valid account binding.');
  }
  return { host: 'github.com', loginDigest: digestContent(auth.login.toLowerCase()) } as const;
}

async function read(reader: CopilotSubscriptionMetadataReader, method: CopilotSubscriptionMetadataMethod) {
  try {
    return await reader.request(method, {});
  } catch {
    throw new NativeBridgeError('capability-unavailable', `Copilot ${method} metadata read failed; no pilot was admitted.`);
  }
}

/** A current account-bound observation, never a pilot admission or a future spending guarantee. */
export async function inspectCopilotSubscription(
  reader: CopilotSubscriptionMetadataReader,
  confirmedLoginDigest?: ContentDigest,
) {
  const status = object(await read(reader, 'status.get'));
  if (status.version !== NATIVE_PROPOSAL_PINS.copilot.cli || status.protocolVersion !== NATIVE_PROPOSAL_PINS.copilot.protocolVersion) {
    throw new NativeBridgeError('unsupported-version', 'Copilot metadata protocol does not match the reviewed pin.');
  }
  const account = accountSnapshot(await read(reader, 'auth.getStatus'));
  if (confirmedLoginDigest !== undefined && account.loginDigest !== confirmedLoginDigest) {
    throw new NativeBridgeError('scope-exceeded', 'Copilot selected a different account from the confirmed binding.');
  }
  const settings = object(object(await read(reader, 'user.settings.get')).settings);
  const setting = settings.model == null ? null : object(settings.model);
  const configuredDefault = setting === null ? null : {
    model: modelId(setting.value), registeredDefault: modelId(setting.default), isDefault: boolean(setting.isDefault),
  };
  const listed = object(await read(reader, 'models.list'));
  if (!Array.isArray(listed.models) || listed.models.length > 256) {
    throw new NativeBridgeError('limit-reached', 'Copilot model metadata exceeds its limit.');
  }
  const ids = new Set<string>();
  let selectedModel: { id: string; policy: string | null } | null = null;
  for (const raw of listed.models) {
    const model = object(raw);
    const id = modelId(model.id);
    if (id === null || ids.has(id)) throw new NativeBridgeError('invalid-input', 'Ambiguous Copilot model metadata.');
    ids.add(id);
    if (id !== configuredDefault?.model) continue;
    const policy = model.policy == null ? null : object(model.policy).state;
    if (policy !== null && !['enabled', 'disabled', 'unconfigured'].includes(String(policy))) {
      throw new NativeBridgeError('invalid-input', 'Unknown Copilot model policy.');
    }
    selectedModel = { id, policy: policy === null ? null : String(policy) };
  }
  const quotas = object(object(await read(reader, 'account.getQuota')).quotaSnapshots);
  const premium = quotas.premium_interactions == null ? null : object(quotas.premium_interactions);
  const quota = premium === null ? null : {
    isUnlimitedEntitlement: boolean(premium.isUnlimitedEntitlement),
    entitlementRequests: amount(premium.entitlementRequests, -1), usedRequests: amount(premium.usedRequests),
    remainingPercentage: amount(premium.remainingPercentage),
    usageAllowedWithExhaustedQuota: boolean(premium.usageAllowedWithExhaustedQuota),
    overageAllowedWithExhaustedQuota: boolean(premium.overageAllowedWithExhaustedQuota),
    overage: amount(premium.overage),
  };
  if (quota !== null && (quota.remainingPercentage > 100 ||
      (quota.entitlementRequests < 0 && (quota.entitlementRequests !== -1 || !quota.isUnlimitedEntitlement)))) {
    throw new NativeBridgeError('invalid-input', 'Inconsistent Copilot entitlement metadata.');
  }
  const after = accountSnapshot(await read(reader, 'auth.getStatus'));
  if (account.loginDigest !== after.loginDigest) throw new NativeBridgeError('scope-exceeded', 'Copilot account changed during metadata inspection.');

  // Quota eligibility does not expose an independently enforced personal billing budget.
  const blockers = ['central-pilot-admission-required', 'billing-controls-review-required'];
  if (quota === null || (!quota.isUnlimitedEntitlement && quota.remainingPercentage <= 0)) blockers.push('included-allowance-unavailable');
  if (configuredDefault?.model == null) blockers.push('effective-default-model-unresolved');
  else if (selectedModel === null || selectedModel.policy === 'disabled' || selectedModel.policy === 'unconfigured') blockers.push('configured-model-unavailable-or-unapproved');
  return {
    host: 'copilot', scope: 'subscription-native-metadata-only', observedAt: new Date().toISOString(),
    cliVersion: NATIVE_PROPOSAL_PINS.copilot.cli, account, accountStable: true,
    configuredDefault, selectedModel, defaultModelScope: 'user-settings-excludes-session-and-managed-overrides',
    quota, billingPolicyScope: 'quota-entitlement-only', noAdditionalChargeProtection: 'unverified',
    modelCalls: 0, pilotAdmission: 'required', blockers,
  } as const;
}
