import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectCodexSubscription } from '../dist/adapters/hosts/codex-subscription-preflight.js';
import { inspectCopilotSubscription } from '../dist/adapters/hosts/copilot-subscription-preflight.js';
import { digestContent } from '../dist/kernel/revisions.js';

function fixture(overrides = {}) {
  const calls = [];
  let accountReads = 0;
  const account = { requiresOpenaiAuth: true, account: { type: 'chatgpt', planType: 'pro', email: 'synthetic-personal@example.invalid' } };
  const model = { id: 'gpt-6-astra', model: 'gpt-6-astra', isDefault: true, multiAgentVersion: 'v2' };
  const limits = { limitId: 'codex', primary: { usedPercent: 0 }, secondary: { usedPercent: 2 }, credits: { hasCredits: false, unlimited: false }, spendControlReached: false };
  const reader = {
    async request(method, params) {
      calls.push({ method, params });
      if (overrides.failure === method) throw new Error('SECRET-native-diagnostic');
      if (method === 'account/read') return structuredClone(++accountReads === 2 ? overrides.after ?? overrides.account ?? account : overrides.account ?? account);
      if (method === 'model/list') return structuredClone(overrides.models?.(params) ?? { data: [model], nextCursor: null });
      if (method === 'account/rateLimits/read') return structuredClone(overrides.usage ?? { ordinaryUsageAllowed: true, rateLimits: limits, rateLimitsByLimitId: { codex: limits }, accountId: 'PRIVATE-account-id', rateLimitUpsell: { secret: 'PRIVATE-banner' } });
      throw new Error(`Unexpected method ${method}`);
    },
  };
  return { calls, reader, account, model, limits };
}

function copilotFixture(overrides = {}) {
  const calls = [];
  let authReads = 0;
  const auth = { isAuthenticated: true, authType: 'user', host: 'https://github.com', login: 'synthetic-personal' };
  const model = { id: 'gpt-6-astra', policy: { state: 'enabled', terms: 'PRIVATE-terms' } };
  const quota = {
    isUnlimitedEntitlement: false, entitlementRequests: 100, usedRequests: 20, remainingPercentage: 80,
    usageAllowedWithExhaustedQuota: false, overageAllowedWithExhaustedQuota: false, overage: 0,
  };
  return {
    calls, auth, model, quota,
    reader: {
      async request(method, params) {
        calls.push({ method, params });
        if (overrides.failure === method) throw new Error('PRIVATE-diagnostic');
        if (method === 'status.get') return overrides.status ?? { version: '1.0.85', protocolVersion: 3 };
        if (method === 'auth.getStatus') return ++authReads === 2 ? overrides.after ?? overrides.auth ?? auth : overrides.auth ?? auth;
        if (method === 'user.settings.get') return { settings: overrides.settings ?? {
          model: { value: 'gpt-6-astra', default: 'auto', isDefault: false }, proxyUrl: { value: 'PRIVATE-proxy' },
        } };
        if (method === 'models.list') return { models: overrides.models ?? [model] };
        if (method === 'account.getQuota') return { quotaSnapshots: overrides.quotas ?? { premium_interactions: quota } };
        throw new Error(`Unexpected method ${method}`);
      },
    },
  };
}

test('Copilot observes quota eligibility and configured model without attesting a billing budget or admitting a pilot', async () => {
  const f = copilotFixture();
  const report = await inspectCopilotSubscription(f.reader, digestContent(f.auth.login));
  assert.equal(report.quota.overageAllowedWithExhaustedQuota, false);
  assert.equal(report.billingPolicyScope, 'quota-entitlement-only');
  assert.equal(report.noAdditionalChargeProtection, 'unverified');
  assert(!Object.hasOwn(report, 'paidOveragesDisabled'));
  assert.deepEqual(report.configuredDefault, { model: 'gpt-6-astra', registeredDefault: 'auto', isDefault: false });
  assert.deepEqual(report.selectedModel, { id: 'gpt-6-astra', policy: 'enabled' });
  assert.equal(report.quota.remainingPercentage, 80);
  assert.equal(report.accountStable, true);
  assert.equal(report.modelCalls, 0);
  assert.equal(report.pilotAdmission, 'required');
  assert.deepEqual(report.blockers, ['central-pilot-admission-required', 'billing-controls-review-required']);
  assert(Number.isFinite(Date.parse(report.observedAt)));
  assert(!JSON.stringify(report).includes('PRIVATE'));
  assert(!JSON.stringify(report).includes(f.auth.login));
  assert.deepEqual(f.calls.map(call => call.method), [
    'status.get', 'auth.getStatus', 'user.settings.get', 'models.list', 'account.getQuota', 'auth.getStatus',
  ]);
  assert(f.calls.every(call => Object.keys(call.params).length === 0));
});

test('Copilot quota flags never attest or disprove independent budget stop-usage protection', async () => {
  const f = copilotFixture();
  for (const overageAllowedWithExhaustedQuota of [false, true]) {
    for (const usageAllowedWithExhaustedQuota of [false, true]) {
      const report = await inspectCopilotSubscription(copilotFixture({ quotas: {
        premium_interactions: { ...f.quota, overageAllowedWithExhaustedQuota, usageAllowedWithExhaustedQuota },
      } }).reader);
      assert.equal(report.quota.overageAllowedWithExhaustedQuota, overageAllowedWithExhaustedQuota);
      assert.equal(report.quota.usageAllowedWithExhaustedQuota, usageAllowedWithExhaustedQuota);
      assert.equal(report.noAdditionalChargeProtection, 'unverified');
      assert(report.blockers.includes('billing-controls-review-required'));
      assert(!Object.hasOwn(report, 'paidOveragesDisabled'));
      assert(!report.blockers.includes('paid-overages-enabled-or-unknown'));
    }
  }
});

test('Copilot missing quota and default metadata stay unknown without model substitution', async () => {
  const report = await inspectCopilotSubscription(copilotFixture({ quotas: {}, settings: {} }).reader);
  assert.equal(report.quota, null);
  assert.equal(report.noAdditionalChargeProtection, 'unverified');
  assert.equal(report.configuredDefault, null);
  assert.equal(report.selectedModel, null);
  assert(report.blockers.includes('billing-controls-review-required'));
  assert(report.blockers.includes('effective-default-model-unresolved'));
});

test('Copilot a null registered default never becomes the first listed model', async () => {
  const f = copilotFixture({ settings: { model: { value: null, default: null, isDefault: true } } });
  const report = await inspectCopilotSubscription(f.reader);
  assert.deepEqual(report.configuredDefault, { model: null, registeredDefault: null, isDefault: true });
  assert.equal(report.selectedModel, null);
  assert(report.blockers.includes('effective-default-model-unresolved'));
});

test('Copilot an unavailable configured model cannot be replaced by a listed model', async () => {
  const f = copilotFixture({ settings: { model: { value: 'missing-model', default: 'auto', isDefault: false } } });
  const report = await inspectCopilotSubscription(f.reader);
  assert.equal(report.configuredDefault.model, 'missing-model');
  assert.equal(report.selectedModel, null);
  assert(report.blockers.includes('configured-model-unavailable-or-unapproved'));
});

test('Copilot confirmed account mismatch fails before quota and settings reads', async () => {
  const f = copilotFixture();
  await assert.rejects(inspectCopilotSubscription(f.reader, digestContent('different-account')), { code: 'scope-exceeded' });
  assert.deepEqual(f.calls.map(call => call.method), ['status.get', 'auth.getStatus']);
});

for (const [name, overrides, code] of [
  ['version drift', { status: { version: '1.0.86', protocolVersion: 3 } }, 'unsupported-version'],
  ['protocol drift', { status: { version: '1.0.85', protocolVersion: 4 } }, 'unsupported-version'],
  ['signed out', { auth: { isAuthenticated: false } }, 'authority-required'],
  ['environment auth', { auth: { ...copilotFixture().auth, authType: 'env' } }, 'scope-exceeded'],
  ['account drift', { after: { ...copilotFixture().auth, login: 'different-account' } }, 'scope-exceeded'],
  ['duplicate models', { models: [copilotFixture().model, copilotFixture().model] }, 'invalid-input'],
  ['missing overage flag', { quotas: { premium_interactions: { ...copilotFixture().quota, overageAllowedWithExhaustedQuota: undefined } } }, 'invalid-input'],
  ['malformed overage flag', { quotas: { premium_interactions: { ...copilotFixture().quota, overageAllowedWithExhaustedQuota: 'false' } } }, 'invalid-input'],
  ['malformed amount', { quotas: { premium_interactions: { ...copilotFixture().quota, usedRequests: NaN } } }, 'invalid-input'],
  ['negative fractional entitlement', { quotas: { premium_interactions: { ...copilotFixture().quota, entitlementRequests: -0.5 } } }, 'invalid-input'],
  ['transport error', { failure: 'account.getQuota' }, 'capability-unavailable'],
]) {
  test(`Copilot metadata rejects ${name} without admitting a session`, async () => {
    await assert.rejects(inspectCopilotSubscription(copilotFixture(overrides).reader), error => {
      assert.equal(error.code, code);
      assert(!error.message.includes('PRIVATE'));
      return true;
    });
  });
}

test('subscription metadata accepts the configured gpt-6-astra without admitting inference or widening the proposal bridge', async () => {
  const f = fixture();
  const report = await inspectCodexSubscription(f.reader, 'gpt-6-astra');
  assert.equal(report.model.model, 'gpt-6-astra');
  assert.equal(report.model.multiAgentVersion, 'v2');
  assert.equal(report.account.planType, 'pro');
  assert(Number.isFinite(Date.parse(report.observedAt)));
  assert.equal(report.modelCalls, 0);
  assert.equal(report.pilotAdmission, 'required');
  assert.equal(report.noAdditionalChargeProtection, 'unverified');
  assert.deepEqual(report.blockers, ['personal-account-confirmation-required', 'billing-controls-review-required', 'central-pilot-admission-required']);
  for (const privateValue of ['synthetic-personal', 'PRIVATE-account-id', 'PRIVATE-banner']) assert(!JSON.stringify(report).includes(privateValue));
  assert.deepEqual(f.calls.map(call => call.method), ['account/read', 'model/list', 'account/rateLimits/read', 'account/read']);
  assert.deepEqual(f.calls[0].params, { refreshToken: false });
  assert.deepEqual(f.calls[2].params, { excludeResetCreditDetails: true, supportsLunaReserve: false });
  assert.deepEqual(f.calls[3].params, { refreshToken: false });
});

test('a confirmed Codex account binding avoids redundant confirmation but preserves billing admission gates', async () => {
  const f = fixture();
  const report = await inspectCodexSubscription(f.reader, 'gpt-6-astra', digestContent(f.account.account.email));
  assert.deepEqual(report.blockers, ['billing-controls-review-required', 'central-pilot-admission-required']);
  assert.equal(report.pilotAdmission, 'required');
  assert.equal(report.noAdditionalChargeProtection, 'unverified');
});

test('a different Codex account cannot reuse the prior personal confirmation', async () => {
  const f = fixture();
  await assert.rejects(inspectCodexSubscription(f.reader, 'gpt-6-astra', digestContent('other@example.invalid')), { code: 'scope-exceeded' });
  assert.deepEqual(f.calls.map(call => call.method), ['account/read']);
});

test('unavailable Codex identity is not mislabeled as an observed account conflict', async () => {
  const f = fixture({ account: { requiresOpenaiAuth: true, account: { type: 'chatgpt', planType: 'pro', email: null } } });
  await assert.rejects(inspectCodexSubscription(f.reader, 'gpt-6-astra', digestContent('confirmed@example.invalid')), { code: 'capability-unavailable' });
  assert.deepEqual(f.calls.map(call => call.method), ['account/read']);
});

test('missing ordinary-usage permission stays unknown even with zero percent used', async () => {
  const f = fixture();
  const missing = fixture({ usage: { rateLimits: f.limits } });
  const report = await inspectCodexSubscription(missing.reader, 'gpt-6-astra');
  assert.equal(report.ordinaryUsageAllowed, null);
  assert(report.blockers.includes('included-usage-not-confirmed'));
});

test('paid and missing credit states cannot be reported as subscription-only protection', async () => {
  const f = fixture();
  for (const credits of [undefined, { hasCredits: true, unlimited: false }, { hasCredits: false, unlimited: true }]) {
    const sample = fixture({ usage: { ordinaryUsageAllowed: true, rateLimits: { ...f.limits, credits } } });
    const report = await inspectCodexSubscription(sample.reader, 'gpt-6-astra');
    assert(report.blockers.includes('paid-credit-fallback-present-or-unknown'));
    assert.equal(report.pilotAdmission, 'required');
  }
});

test('no subscription login never triggers login, model selection or quota reads', async () => {
  for (const account of [null, { type: 'apiKey' }, { type: 'amazonBedrock' }]) {
    const f = fixture({ account: { requiresOpenaiAuth: true, account } });
    const report = await inspectCodexSubscription(f.reader, 'gpt-6-astra');
    assert.deepEqual(report.blockers, ['personal-subscription-login-required']);
    assert.deepEqual(f.calls.map(call => call.method), ['account/read']);
    assert.equal(report.model, null);
  }
});

test('model discovery never substitutes another model for the configured default', async () => {
  const f = fixture();
  const report = await inspectCodexSubscription(f.reader, 'different-default');
  assert.equal(report.model, null);
  assert(report.blockers.includes('configured-default-model-unavailable'));
});

test('an unset configured model uses only the explicitly reported catalog default', async () => {
  const f = fixture();
  assert.equal((await inspectCodexSubscription(f.reader, null)).model.model, 'gpt-6-astra');
});

test('missing account identity remains a separate admission blocker', async () => {
  const f = fixture();
  f.account.account.email = null;
  const sample = fixture({ account: f.account });
  const report = await inspectCodexSubscription(sample.reader, 'gpt-6-astra');
  assert.equal(report.account.identityDigest, null);
  assert(report.blockers.includes('account-identity-unavailable'));
});

test('bounded model pagination preserves exact default matching', async () => {
  const f = fixture();
  const paginated = fixture({ models: params => params.cursor === null
    ? { data: [{ ...f.model, id: 'other', model: 'other', isDefault: false }], nextCursor: 'page-2' }
    : { data: [f.model], nextCursor: null } });
  assert.equal((await inspectCodexSubscription(paginated.reader, 'gpt-6-astra')).model.model, 'gpt-6-astra');
  assert.equal(paginated.calls.filter(call => call.method === 'model/list').length, 2);
});

for (const [name, overrides, code] of [
  ['duplicate models', { models: () => ({ data: [fixture().model, fixture().model], nextCursor: null }) }, 'invalid-input'],
  ['repeated cursor', { models: () => ({ data: [], nextCursor: 'repeat' }) }, 'invalid-input'],
  ['too many pages', { models: params => ({ data: [], nextCursor: `${params.cursor ?? ''}next` }) }, 'limit-reached'],
  ['too many models', { models: () => ({ data: Array(51).fill(fixture().model), nextCursor: null }) }, 'limit-reached'],
  ['bad usage boolean', { usage: { ordinaryUsageAllowed: 'true', rateLimits: fixture().limits } }, 'invalid-input'],
  ['missing credit booleans', { usage: { rateLimits: { credits: {} } } }, 'invalid-input'],
  ['unknown subscription plan', { account: { requiresOpenaiAuth: true, account: { type: 'chatgpt', planType: 'unreviewed', email: null } } }, 'invalid-input'],
  ['ambiguous default', { models: () => ({ data: [fixture().model, { ...fixture().model, id: 'other' }], nextCursor: null }) }, 'invalid-input'],
  ['too many quota buckets', { usage: { rateLimits: fixture().limits, rateLimitsByLimitId: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [i, fixture().limits])) } }, 'invalid-input'],
  ['negative usage', { usage: { rateLimits: { primary: { usedPercent: -1 } } } }, 'invalid-input'],
  ['custom unauthenticated provider', { account: { requiresOpenaiAuth: false } }, 'scope-exceeded'],
  ['account drift', { after: { requiresOpenaiAuth: true, account: { type: 'chatgpt', planType: 'pro', email: 'other@example.invalid' } } }, 'scope-exceeded'],
  ['transport error', { failure: 'account/rateLimits/read' }, 'capability-unavailable'],
]) {
  test(`subscription metadata fails explicitly for ${name}`, async () => {
    await assert.rejects(inspectCodexSubscription(fixture(overrides).reader, 'gpt-6-astra'), error => {
      assert.equal(error.code, code);
      assert(!error.message.includes('SECRET'));
      return true;
    });
  });
}
