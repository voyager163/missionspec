import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm, readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { digestJson as hash, digest } from '../definition.mjs';
import { privateLinkPhase } from '../private-link.mjs';
import { privateLinkAzureIO, privateLinkTargetKey, preparePrivateLinkPhase, checkPrivateLinkPhase,
  executePrivateLinkPhase, reconcilePrivateLinkPhase, recoverPrivateLinkPhase, runPrivateLinkControl } from '../private-link-controller.mjs';
import { verifyPrivateLinkControlEvidence } from '../private-link-controller.mjs';
import { privateLinkReadRequests } from '../private-link-readback.mjs';
import { nsgAdoptionFixture, adoptedSnapshot } from './private-link-nsg-adoption.fixture.mjs';
import { privateSnapshotFixture } from './private-link.fixture.mjs';

const x = await nsgAdoptionFixture(() => {}, true), { f } = x, stage = 'create-environment', at = x.io.now();
const proposal = await reconcilePrivateLinkPhase(f.c, f.context, x.adoptedEvidence, x.original, x.io);
const resolution = await recoverPrivateLinkPhase(f.c, f.context, x.adoptedEvidence, x.original, proposal, {
  version: 1, action: 'record-exact-private-link-no-submission-without-replay', proposalSha256: hash(proposal),
  sourceSha256: f.source, pendingHeadSha256: hash(proposal.pendingHead), approvedAt: new Date(at).toISOString(),
  expiresAt: new Date(at + 600000).toISOString(),
}, { ...x.io, resolveNoSubmission: async () => {} });
const fixed = privateLinkPhase(f.c, f.context, stage), attemptId = randomUUID();
const continuation = { version: 1, kind: 'reviewed-private-link-no-submission-continuation', attemptId, resolution,
  review: { version: 1, action: 'continue-exact-known-not-submitted-private-link-phase', configSha256: hash(f.c),
    planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin), stage, attemptId,
    resolutionSha256: hash(resolution), priorIntentSha256: hash(x.original.intent), pendingHeadSha256: hash(proposal.pendingHead),
    fixedPhaseSha256: hash(fixed), requestSha256: hash(fixed.request), sourceSha256: f.source,
    approvedAt: new Date(at).toISOString(), expiresAt: new Date(at + 600000).toISOString() } };
const phase = preparePrivateLinkPhase(f.c, f.context, x.adoptedEvidence, stage, null, continuation);
const proof = await checkPrivateLinkPhase(f.c, f.context, x.adoptedEvidence, phase, { ...x.io,
  head: async () => proposal.pendingHead });
const approval = { version: 1, action: `execute-exact-private-link-${stage}`, configSha256: hash(f.c),
  planSha256: f.context.plan.planSha256, phaseSha256: hash(phase), bindingSha256: hash(proof.binding), sourceSha256: f.source,
  requestSha256: hash(phase.request), approvedAt: new Date(at).toISOString(), expiresAt: new Date(at + 600000).toISOString() };

async function harness(t) {
  const evidence = structuredClone(x.adoptedEvidence), p = structuredClone(phase), preflight = structuredClone(proof), reviewed = structuredClone(approval);
  const directory = `infrastructure/arm/telemetry/tests/.private-link-validation-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  const target = privateLinkTargetKey(f.context), original = p.continuation.resolution.original, pending = p.continuation.resolution.proposal.pendingHead;
  const files = new Map([
    [`private-link-head-${target}.json`, pending],
    [`private-link-fence-${target}.json`, { version: 1, targetKey: target, stage, phase: original.phase,
      intent: original.intent, intentSha256: hash(original.intent) }],
    [`private-link-intent-${hash({ target, stage })}.json`, { phase: original.phase, intent: original.intent }],
    [`private-link-no-submission-${hash(original.intent)}.json`, { pending, record: p.continuation.resolution }],
    [`private-link-nsg-adoption-${target}.json`, evidence.externalAdoption],
  ]);
  let now = at, source = f.source, journal = null, writes = 0, captured = null;
  let invoked = () => { throw new Error('UNIT_STOP_AT_EXACT_INVOKE'); };
  const input = { publication: x.io.publication, proof: preflight, approval: reviewed, continuation: p.continuation,
    costReview: preflight.costReview, costEvidence: preflight.costEvidence, migrationReview: preflight.migrationReview };
  const options = { now: () => now, sourceDigest: async () => source,
    store: { root: directory, read: async (_root, name) => structuredClone(files.get(name) ?? null),
      save: async (_root, name, value) => { files.set(name, structuredClone(value)); },
      saveImmutable: async (_root, name, value) => { assert(!files.has(name)); files.set(name, structuredClone(value)); } } };
  const adapter = privateLinkAzureIO(f.c, f.context, evidence, p, directory, input, async args => {
    writes++;
    assert.equal(args[args.indexOf('--method') + 1], 'PUT');
    const body = JSON.parse(await readFile(args[args.indexOf('--body') + 1].slice(1), 'utf8'));
    assert.deepEqual(body, fixed.request.body);
    return invoked();
  }, options);
  const io = { ...x.io, now: options.now, sourceDigest: options.sourceDigest, head: adapter.head,
    reserve: adapter.reserve, journal: async () => journal, saveJournal: async value => { journal = structuredClone(value); },
    write: async (...args) => { captured = args; return adapter.write(...args); } };
  return { evidence, phase: p, proof: preflight, approval: reviewed, input, options, files, adapter, io, directory, target,
    setNow: value => { now = value; }, setSource: value => { source = value; }, setInvoked: value => { invoked = value; }, get writes() { return writes; },
    get journal() { return journal; }, get captured() { return captured; },
    execute: () => executePrivateLinkPhase(f.c, f.context, evidence, p, preflight, reviewed, io) };
}

test('operation-local continuation validates once and invokes only the original fixed body without freezing caller phase/proof', async t => {
  const q = await harness(t), before = hash({ evidence: q.evidence, phase: q.phase, proof: q.proof, approval: q.approval });
  await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  assert.equal(q.writes, 1); assert.equal(q.journal.dispatchAttempted, true);
  assert.equal(q.journal.failure.code, 'UNIT_STOP_AT_EXACT_INVOKE');
  assert.equal(hash({ evidence: q.evidence, phase: q.phase, proof: q.proof, approval: q.approval }), before);
  assert.equal(Object.isFrozen(q.phase), false); assert.equal(Object.isFrozen(q.proof), false); assert.equal(Object.isFrozen(q.approval), false);
  assert.equal(Object.isFrozen(q.captured[0]), true);
  await assert.rejects(q.execute(), /INTENT_REPLAY_FORBIDDEN/);
  assert.equal(q.writes, 1);
  await assert.rejects(q.adapter.write(...q.captured));
  assert.equal(q.writes, 1);
});

test('forged or serialized validation tokens never admit an unchecked phase/body', async t => {
  for (const token of [{}, { validated: true }, JSON.parse(JSON.stringify({ phaseSha256: hash(phase) }))]) {
    const q = await harness(t);
    await assert.rejects(q.adapter.write(q.phase, () => {}, async () => {}, async () => {}, at + 120000, token));
    assert.equal(q.writes, 0); assert.equal(q.journal, null);
  }
});

test('successful adopted continuation fully verifies and appends its new record after operation-local reuse', async t => {
  const q = await harness(t), after = privateSnapshotFixture(f, stage, at), n = f.context.plan.topology.ids;
  for (const [id, value] of Object.entries(x.current.resources)) if (value && after.resources[id]) {
    if (value.systemData) after.resources[id].systemData = structuredClone(value.systemData);
    if (value.properties?.createdOn) after.resources[id].properties.createdOn = value.properties.createdOn;
  }
  adoptedSnapshot(x, after);
  const descriptor = fixed.resources[0], deployment = { id: fixed.deploymentId, properties: { provisioningState: 'Succeeded',
    mode: 'Incremental', templateHash: hash(fixed.template), correlationId: 'UNIT immutable continuation',
    timestamp: new Date(at).toISOString(), outputResources: [{ id: descriptor.id }] } };
  const operations = { value: [{ id: `${fixed.deploymentId}/operations/unit`, operationId: 'unit',
    properties: { provisioningState: 'Succeeded', provisioningOperation: 'Create', statusCode: 'OK',
      targetResource: { id: descriptor.id, resourceType: descriptor.type, resourceName: descriptor.expected.name } } }] };
  const requests = privateLinkReadRequests(f.c, f.context), read = q.io.read;
  q.setInvoked(() => ({}));
  q.io.read = async (request, ...args) => {
    if (!q.writes) return read(request, ...args);
    if (request.id === fixed.deploymentId) return deployment;
    if (request.id === fixed.deploymentId + '/operations') return operations;
    if (Object.hasOwn(after.resources, request.id)) return structuredClone(after.resources[request.id]);
    if (Object.hasOwn(after.managed, request.id)) return structuredClone(after.managed[request.id]);
    const list = Object.entries(requests).find(([, value]) => value.id === request.id);
    if (list) return structuredClone(after.lists[list[0]]);
    const suffix = '/providers/Microsoft.Insights/diagnosticSettings';
    if (request.id.endsWith(suffix) && Object.hasOwn(after.diagnostics, request.id.slice(0, -suffix.length))) {
      return structuredClone(after.diagnostics[request.id.slice(0, -suffix.length)]);
    }
    return read(request, ...args);
  };
  q.io.append = q.adapter.append;
  const result = await q.execute(), completed = { ...q.evidence, records: [...q.evidence.records, result] };
  assert.equal(q.writes, 1); assert.equal(result.journal.outcome, 'readback-qualified');
  assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, completed, at).after.resources[n.environment].id, n.environment);
  const bad = structuredClone(completed);
  bad.records.at(-1).preflight.policy.qualified = false;
  assert.throws(() => verifyPrivateLinkControlEvidence(f.c, f.context, bad, at));
});

test('operation-local validation rejects input/adapter substitution after await before any dispatch', async t => {
  for (const [name, mutate] of [
    ['body', q => { q.phase.request.body.properties.mode = 'Complete'; }],
    ['phase', q => { q.phase.stage = 'disable-storage-public'; }],
    ['proof', q => { q.proof.binding.policySha256 = digest('UNIT substitution'); }],
    ['cost review', q => { q.proof.costReview.budgetTargets.migration.project += 1; }],
    ['approval', q => { q.approval.requestSha256 = digest('UNIT substitution'); }],
    ['evidence wrapper', q => { q.evidence.planSha256 = digest('UNIT substitution'); }],
    ['adapter proof swap', q => { q.input.proof = { ...q.proof, phaseSha256: digest('UNIT substitution') }; }],
    ['adapter approval swap', q => { q.input.approval = { ...q.approval, sourceSha256: digest('UNIT substitution') }; }],
  ]) await t.test(name, async t => {
    const q = await harness(t), reserve = q.io.reserve;
    q.io.reserve = async (...args) => { const pending = await reserve(...args); await Promise.resolve(); mutate(q); return pending; };
    await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
    assert.equal(q.writes, 0); assert.equal(q.journal.dispatchAttempted, false);
    assert.equal(q.journal.failure.code, 'PRIVATE_LINK_DISPATCH_VALIDATION_CHANGED');
  });
});

test('source, head, fresh policy/permission/privacy and deadlines remain live after operation validation', async t => {
  for (const [name, change, failure] of [
    ['source after reserve', q => { const run = q.io.reserve; q.io.reserve = async (...args) => { const p = await run(...args); q.setSource(digest('UNIT source changed')); return p; }; }, /SOURCE_CHANGED/],
    ['source changes during final reads', q => { const run = q.io.read; q.io.read = async (...args) => {
      const value = await run(...args); q.setSource(digest('UNIT source changed after await')); return value; }; }, /SOURCE_OR_DEADLINE_CHANGED/],
    ['physical head swap', q => { const run = q.io.reserve; q.io.reserve = async (...args) => { const p = await run(...args);
      q.files.set(`private-link-head-${q.target}.json`, { ...p, intentSha256: digest('UNIT different head') }); return p; }; }, /HEAD_CHANGED/],
    ['fresh deny assignment', q => { const run = q.io.read; q.io.read = (request, ...args) => request.id.endsWith('/denyAssignments') ?
      Promise.resolve({ value: [{ id: 'UNIT deny' }] }) : run(request, ...args); }, /GOVERNANCE_CHANGED|DENY_ASSIGNMENT/],
    ['fresh policy change', q => { const run = q.io.read; q.io.read = (request, ...args) => request.id.endsWith('/policyAssignments') ?
      Promise.resolve({ value: [{ id: 'UNIT incomplete changed policy' }] }) : run(request, ...args); }, /POLICY/],
    ['fresh targeted flow log', q => { const run = q.io.read; q.io.read = (request, ...args) => request.id.endsWith('/flowLogs') ?
      Promise.resolve({ value: [{ id: x.watcherId + '/flowLogs/unit', type: 'Microsoft.Network/networkWatchers/flowLogs',
        properties: { enabled: true, targetResourceId: x.nsg.id } }] }) : run(request, ...args); }, /TARGET_FLOW_LOG_FORBIDDEN/],
    ['fresh spend exceeds reviewed budget', q => { const run = q.io.read; q.io.read = async (request, ...args) => {
      const value = await run(request, ...args);
      if (value?.type === 'Microsoft.Consumption/budgets') value.properties.currentSpend.amount = 999;
      return value; }; }, /SPEND_REVIEW_REQUIRED/],
    ['final read deadline', q => { const run = q.io.write; q.io.write = (...args) => { q.setNow(args[4]); return run(...args); }; }, /DEADLINE|EXPIRED/],
    ['expired proof before reservation', q => q.setNow(proof.startedAt + 300001), /STALE_EVIDENCE/],
    ['expired approval before reservation', q => q.setNow(Date.parse(approval.expiresAt)), /STALE_EVIDENCE|REVIEW_EXPIRED/],
    ['cancel before invoke', q => { q.io.cancelled = () => true; }, /OPERATION_EXPIRED/],
    ['deadline after durable marker await', q => { const run = q.io.saveJournal; q.io.saveJournal = async value => {
      await run(value); if (value.dispatchAttempted === null) q.setNow(Date.parse(approval.expiresAt)); }; }, /DISPATCH_GUARD_REQUIRED/],
    ['body changes after durable marker await', q => { const run = q.io.saveJournal; q.io.saveJournal = async value => {
      await run(value); if (value.dispatchAttempted === null) q.phase.request.body.properties.mode = 'Complete'; }; }, /DISPATCH_VALIDATION_CHANGED/],
  ]) await t.test(name, async t => {
    const q = await harness(t); change(q);
    await assert.rejects(q.execute());
    assert.equal(q.writes, 0);
    if (q.journal) { assert.equal(q.journal.dispatchAttempted, false); assert.match(q.journal.failure.code, failure); }
  });
});

test('a checked token cannot be used with another adapter context or phase', async t => {
  const q = await harness(t), write = q.io.write;
  const otherContext = structuredClone(f.context);
  const other = privateLinkAzureIO(f.c, otherContext, q.evidence, q.phase, q.directory, q.input,
    async () => assert.fail('Foreign adapter must not invoke'), q.options);
  q.io.write = async (...args) => {
    await assert.rejects(other.write(...args), /DISPATCH_VALIDATION_CHANGED/);
    const changed = structuredClone(args[0]); changed.request.id += '-other';
    await assert.rejects(q.adapter.write(changed, ...args.slice(1)), /DISPATCH_VALIDATION_CHANGED/);
    await assert.rejects(q.adapter.write(args[0], ...args.slice(1, 5), structuredClone(args[5])));
    return write(...args);
  };
  await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  assert.equal(q.writes, 1);
});

test('public dispatch candidate construction still rejects invalid continuation before invoking or reserving', async t => {
  const directory = `infrastructure/arm/telemetry/.operator-private/revision-20261003-validation-${randomUUID().slice(0, 8)}`;
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir('infrastructure/opentofu/telemetry/.operator-private', { recursive: true, mode: 0o700 });
  const bad = structuredClone(continuation); bad.resolution.original.journal.dispatchAttempted = null;
  await assert.rejects(runPrivateLinkControl(f.c, f.context, x.adoptedEvidence, stage, 'execute', directory,
    { continuation: bad, publication: x.io.publication, proof, approval, costReview: proof.costReview,
      costEvidence: proof.costEvidence, migrationReview: proof.migrationReview },
    { now: () => at, invoke: async () => assert.fail('Invalid continuation must not invoke') }));
});
