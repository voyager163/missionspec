import assert from 'node:assert/strict';
import test from 'node:test';
import { dispatchPrivateLinkOperation, PRIVATE_LINK_CONTROL_COMMANDS, PRIVATE_LINK_RUNTIME_COMMANDS,
  PRIVATE_LINK_NSG_COMMANDS } from '../controller.mjs';
import { baseFixture } from './durable-queue.fixture.mjs';

const c = baseFixture().c;
function fixture(inputs = {}) {
  const context = { plan: 'opaque passed only to production verifier', origin: 'unchanged' };
  const evidence = { records: [] }, calls = [], writes = [];
  let runtimeResult = { kind: 'test-only-preparation' };
  const files = { 'private-link-control-context.json': context, 'private-link-control-evidence.json': evidence,
    'private-link-control-inputs.json': inputs, 'private-link-runtime-inputs.json': inputs,
    'private-link-nsg-adoption-inputs.json': inputs };
  const io = { directory: async value => { calls.push(['directory', value]); return value; },
    read: async (_directory, name) => { calls.push(['read', name]); assert(Object.hasOwn(files, name)); return files[name]; },
    immutable: async (_directory, name, value) => { writes.push({ name, value }); },
    control: async (...args) => { calls.push(['control', ...args]); return { kind: 'test-only-control-result' }; },
    runtime: async (...args) => { calls.push(['runtime', ...args]); return runtimeResult; },
    nsg: async (...args) => { calls.push(['nsg', ...args]); return { kind: 'test-only-nsg-result' }; } };
  return { context, evidence, calls, writes, io, result: value => { runtimeResult = value; } };
}

test('Private Link routing validates fixed families before directory access and cannot pass transport overrides from JSON', async () => {
  const f = fixture();
  for (const [operation, stage] of [['execute-private-link', 'private-link-migration'],
    ['retire-private-link', 'not-a-stage'], ['publish-private-link-image', 'retire-nsp-rule'],
    ['arbitrary-command', 'private-link-runtime']]) {
    await assert.rejects(dispatchPrivateLinkOperation(c, operation, stage, 'unused', f.io), /FIXED_PHASE_COMMAND_REQUIRED/);
  }
  assert.deepEqual(f.calls, []);
  const injected = fixture({ publication: {}, costReview: {}, costEvidence: {}, migrationReview: {}, options: { invoke: 'untrusted' } });
  await assert.rejects(dispatchPrivateLinkOperation(c, 'check-private-link', 'review-migration', 'unit', injected.io), /CLOSED_INPUT_REQUIRED/);
  assert(!injected.calls.some(value => value[0] === 'control'));
});

test('NSG observation and adoption require their closed read-only family and explicit original journal directory', async () => {
  for (const [command, action] of Object.entries(PRIVATE_LINK_NSG_COMMANDS)) {
    const inputs = { original: {}, originalDirectory: 'original-relative-dir', publication: {}, policyRevision: null,
      costReview: {}, costEvidence: {}, migrationReview: {},
      ...(action === 'observe-nsg-adoption' ? { provenance: {} } : { proposal: {}, review: {} }) };
    const f = fixture(inputs);
    await assert.rejects(dispatchPrivateLinkOperation(c, command, 'create-environment', 'new-relative-dir', f.io),
      /FIXED_PHASE_COMMAND_REQUIRED/);
    assert.deepEqual(f.calls, []);
    await dispatchPrivateLinkOperation(c, command, 'private-link-nsg-adoption', 'new-relative-dir', f.io);
    assert.deepEqual(f.calls.at(-1), ['nsg', c, f.context, f.evidence, action, 'new-relative-dir', inputs]);
    assert.deepEqual(f.writes, []);
    for (const change of [
      value => { value.options = {}; }, value => { value.request = { method: 'DELETE' }; },
      value => { delete value.originalDirectory; }, value => { delete value.policyRevision; },
    ]) {
      const altered = structuredClone(inputs); change(altered);
      const invalid = fixture(altered);
      await assert.rejects(dispatchPrivateLinkOperation(c, command, 'private-link-nsg-adoption', 'new', invalid.io),
        /CLOSED_INPUT_REQUIRED/);
      assert(!invalid.calls.some(value => value[0] === 'nsg'));
    }
  }
});

test('only adopted-evidence reconciliation forwards the explicit original directory', async () => {
  for (const command of ['reconcile-private-link', 'recover-private-link']) {
    const inputs = { publication: {}, costReview: {}, costEvidence: {}, migrationReview: {}, original: {},
      originalDirectory: 'original-relative-dir',
      ...(command === 'recover-private-link' ? { proposal: {}, recoveryReview: {} } : {}) };
    const f = fixture(inputs); f.evidence.version = 2;
    await dispatchPrivateLinkOperation(c, command, 'create-environment', 'new-relative-dir', f.io);
    assert.deepEqual(f.calls.at(-1).at(-1), inputs);
    delete inputs.originalDirectory;
    const missing = fixture(inputs); missing.evidence.version = 2;
    await assert.rejects(dispatchPrivateLinkOperation(c, command, 'create-environment', 'new', missing.io), /CLOSED_INPUT_REQUIRED/);
  }
  const forbidden = fixture({ originalDirectory: 'old' }); forbidden.evidence.version = 2;
  await assert.rejects(dispatchPrivateLinkOperation(c, 'prepare-private-link', 'create-environment', 'new', forbidden.io),
    /CLOSED_INPUT_REQUIRED/);
});

test('control routes exact current context, evidence and stage-specific inputs to the concrete driver', async () => {
  for (const [command, action] of Object.entries(PRIVATE_LINK_CONTROL_COMMANDS)) {
    const stage = action === 'retire' ? 'retire-nsp-rule' : 'create-network';
    const inputs = action === 'prepare' ? {} : { publication: {}, costReview: {}, costEvidence: {}, migrationReview: {},
      ...(['execute', 'retire'].includes(action) ? { proof: {}, approval: {} } : {}),
      ...(['reconcile', 'recover'].includes(action) ? { original: {} } : {}),
      ...(action === 'recover' ? { proposal: {}, recoveryReview: {} } : {}) };
    const f = fixture(inputs);
    await dispatchPrivateLinkOperation(c, command, stage, 'unit-relative-dir', f.io);
    assert.deepEqual(f.calls.at(-1), ['control', c, f.context, f.evidence, stage, action, 'unit-relative-dir', inputs]);
    assert.deepEqual(f.writes, []);
  }
});

test('control routing passes a reviewed policy revision without exposing arbitrary driver options', async () => {
  for (const command of ['prepare-private-link', 'check-private-link']) {
    const inputs = { ...(command === 'check-private-link'
      ? { publication: {}, costReview: {}, costEvidence: {}, migrationReview: {} } : {}),
    policyRevision: { bound: 'validated by the concrete control driver' } };
    const f = fixture(inputs);
    await dispatchPrivateLinkOperation(c, command, 'create-network', 'unit', f.io);
    assert.deepEqual(f.calls.at(-1).at(-1), inputs);
    const injected = fixture({ ...inputs, options: { skipPublication: true } });
    await assert.rejects(dispatchPrivateLinkOperation(c, command, 'create-network', 'unit', injected.io),
      /CLOSED_INPUT_REQUIRED/);
    assert(!injected.calls.some(value => value[0] === 'control'));
  }
});

test('known-no-submission continuation is data only for forward control routes', async () => {
  for (const [command, action] of Object.entries(PRIVATE_LINK_CONTROL_COMMANDS)) {
    const inputs = { ...(action === 'prepare' ? {} : { publication: {}, costReview: {}, costEvidence: {}, migrationReview: {} }),
      ...(['execute', 'retire'].includes(action) ? { proof: {}, approval: {} } : {}),
      ...(['reconcile', 'recover'].includes(action) ? { original: {} } : {}),
      ...(action === 'recover' ? { proposal: {}, recoveryReview: {} } : {}),
      continuation: { version: 1, kind: 'reviewed-private-link-no-submission-continuation',
        attemptId: '00000000-0000-4000-8000-000000000099', resolution: {}, review: {} } };
    const f = fixture(inputs), stage = action === 'retire' ? 'retire-nsp-rule' : 'create-network';
    if (['reconcile', 'recover'].includes(action)) {
      await assert.rejects(dispatchPrivateLinkOperation(c, command, stage, 'unit', f.io), /CLOSED_INPUT_REQUIRED/);
      assert(!f.calls.some(value => value[0] === 'control'));
    } else {
      await dispatchPrivateLinkOperation(c, command, stage, 'unit', f.io);
      assert.deepEqual(f.calls.at(-1).at(-1), inputs);
      const injected = fixture({ ...inputs, options: { invoke: 'untrusted' } });
      await assert.rejects(dispatchPrivateLinkOperation(c, command, stage, 'unit', injected.io), /CLOSED_INPUT_REQUIRED/);
      assert(!injected.calls.some(value => value[0] === 'control'));
    }
  }
});

test('runtime routing persists returned publication separately and never labels failed qualification successful', async () => {
  for (const [command, action] of Object.entries(PRIVATE_LINK_RUNTIME_COMMANDS)) {
    const f = fixture({ supplied: 'driver validates its closed schema' });
    f.result({ kind: 'test-only-runtime-record', outcome: 'qualified-private-delivery-disabled' });
    const result = await dispatchPrivateLinkOperation(c, command, 'private-link-runtime', 'unit-relative-dir', f.io);
    assert.deepEqual(f.calls.at(-1), ['runtime', c, f.context, f.evidence, action, 'unit-relative-dir',
      { supplied: 'driver validates its closed schema' }]);
    assert.equal(f.writes.length, action === 'publish-image' ? 1 : 0);
    if (action === 'publish-image') assert.deepEqual(f.writes[0], { name: 'private-link-published-candidate.json', value: result });
  }
  const f = fixture();
  f.result({ outcome: 'stopped-disabled-unqualified' });
  await assert.rejects(dispatchPrivateLinkOperation(c, 'qualify-private-link-window',
    'private-link-runtime', 'unit', f.io), /PRIVATE_LINK_WINDOW_STOPPED/);
});

test('public-control cleanup and reconciliation routes use only the runtime family', async () => {
  const recoveryId = '00000000-0000-4000-8000-000000000099';
  for (const [command, action, inputs] of [
    ['prepare-private-link-public-cleanup', 'prepare-public-cleanup', { recoveryId }],
    ['recover-private-link-public-cleanup', 'recover-public-cleanup', { recoveryId, approval: {} }],
    ['reconcile-private-link-public-probe', 'reconcile-public-probe', { reconciliationId: recoveryId }],
  ]) {
    const f = fixture(inputs);
    await assert.rejects(dispatchPrivateLinkOperation(c, command, 'retire-old-receiver', 'unit', f.io),
      /FIXED_PHASE_COMMAND_REQUIRED/);
    assert.deepEqual(f.calls, []);
    await dispatchPrivateLinkOperation(c, command, 'private-link-runtime', 'unit', f.io);
    assert.deepEqual(f.calls.at(-1), ['runtime', c, f.context, f.evidence, action, 'unit', inputs]);
    assert.deepEqual(f.writes, []);
  }
});

test('runtime held errors propagate and successful cleanup does not become window qualification', async () => {
  for (const [command, code] of [
    ['qualify-private-link-window', 'PRIVATE_RUNTIME_QUALIFICATION_HELD'],
    ['qualify-private-link-window-continuation', 'PRIVATE_RUNTIME_QUALIFICATION_HELD'],
    ['recover-private-link-disable', 'PRIVATE_DISABLE_RECOVERY_HELD'],
    ['recover-private-link-public-cleanup', 'PRIVATE_PUBLIC_CLEANUP_RECOVERY_HELD'],
    ['reconcile-private-link-public-probe', 'PRIVATE_PUBLIC_CONTROL_STILL_PRESENT'],
  ]) {
    const f = fixture(), error = new Error(code);
    f.io.runtime = async () => { throw error; };
    await assert.rejects(dispatchPrivateLinkOperation(c, command, 'private-link-runtime', 'unit', f.io),
      actual => actual === error);
    assert.deepEqual(f.writes, []);
  }
  for (const [command, outcome] of [
    ['recover-private-link-disable', 'recovered-disabled-original-outcome-retained'],
    ['recover-private-link-public-cleanup', 'public-control-absent-original-history-retained'],
  ]) {
    const f = fixture(), record = { outcome, qualification: false, failure: null };
    f.result(record);
    assert.equal(await dispatchPrivateLinkOperation(c, command, 'private-link-runtime', 'unit', f.io), record);
    assert.deepEqual(f.writes, []);
  }
});

test('never-enabled continuation routes only fixed runtime operations and does not reclassify stopped results', async () => {
  for (const [command, action] of [
    ['prepare-private-link-window-continuation', 'prepare-window-continuation'],
    ['qualify-private-link-window-continuation', 'qualify-window-continuation'],
  ]) {
    const f = fixture({ continuationApproval: { checkedByRuntime: true } });
    await assert.rejects(dispatchPrivateLinkOperation(c, command, 'retire-old-receiver', 'unit', f.io), /FIXED_PHASE_COMMAND_REQUIRED/);
    assert.deepEqual(f.calls, []);
    f.result({ outcome: 'qualified-private-delivery-disabled' });
    await dispatchPrivateLinkOperation(c, command, 'private-link-runtime', 'unit', f.io);
    assert.deepEqual(f.calls.at(-1).slice(0, 6), ['runtime', c, f.context, f.evidence, action, 'unit']);
    assert.equal(f.calls.at(-1).length, 7);
    assert.deepEqual(f.writes, []);
    if (action === 'qualify-window-continuation') {
      f.result({ outcome: 'stopped-disabled-unqualified' });
      await assert.rejects(dispatchPrivateLinkOperation(c, command, 'private-link-runtime', 'unit', f.io), /PRIVATE_LINK_WINDOW_STOPPED/);
    }
  }
});


test('reviewed runtime names are forwarded only for the five post-runtime control stages', async () => {
  const stages = ['retire-old-receiver', 'retire-old-environment', 'set-project-steady-budget', 'set-telemetry-steady-budget', 'record-migration'];
  for (const [command, action] of Object.entries(PRIVATE_LINK_CONTROL_COMMANDS)) {
    for (const stage of [...stages, 'create-network']) {
      const allowed = stages.includes(stage);
      const inputs = { ...(action === 'prepare' ? {} : { publication: {}, costReview: {}, costEvidence: {}, migrationReview: {},
        ...(allowed ? { runtimeCompletion: {} } : {}),
        ...(['execute', 'retire'].includes(action) ? { proof: {}, approval: {} } : {}),
        ...(['reconcile', 'recover'].includes(action) ? { original: {} } : {}),
        ...(action === 'recover' ? { proposal: {}, recoveryReview: {} } : {}) }), nameProjection: { version: 1 } };
      const f = fixture(inputs);
      if (allowed) {
        await dispatchPrivateLinkOperation(c, command, stage, 'unit', f.io);
        assert.deepEqual(f.calls.at(-1).at(-1), inputs);
      } else {
        await assert.rejects(dispatchPrivateLinkOperation(c, command, stage, 'unit', f.io), /CLOSED_INPUT_REQUIRED/);
        assert(!f.calls.some(value => value[0] === 'control'));
      }
    }
  }
});
