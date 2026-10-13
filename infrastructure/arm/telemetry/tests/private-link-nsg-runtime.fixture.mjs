import assert from 'node:assert/strict';
import { mkdir, rm, readdir, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { digest, digestJson, json } from '../definition.mjs';
import { load, MAX_PRIVATE_ARTIFACT_BYTES } from '../controller.mjs';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';
import { privateLinkPhase, PRIVATE_LINK_CONTROL_STAGES as STAGES } from '../private-link.mjs';
import { privateLinkReadRequests } from '../private-link-readback.mjs';
import { preparePrivateLinkPhase, checkPrivateLinkPhase, executePrivateLinkPhase, reconcilePrivateLinkPhase,
  recoverPrivateLinkPhase, verifyPrivateLinkControlEvidence, privateLinkHead, privateLinkTargetKey,
  privateLinkAzureIO, verifyPrivateLinkRuntimePrerequisites, currentPrivateLinkRuntimeProof, readPrivateLinkHead } from '../private-link-controller.mjs';
import { adoptedSnapshot, adoptedIO, retainedReadInvoke } from './private-link-nsg-adoption.fixture.mjs';
import { privateSnapshotFixture, privateControlHarness } from './private-link.fixture.mjs';
import { privateRuntimeCompletionFixture } from './private-link-runtime.fixture.mjs';

const hash = digestJson;
export async function verifyNsgRuntimeCase(t, scenario) {
  const x = scenario, f = x.f;
  const evidence = x.adoptedEvidence, original = x.original, bytes = json(original), six = json(x.evidence);
  const io = { ...x.io, resolveNoSubmission: async () => {} };
  const proposal = await reconcilePrivateLinkPhase(f.c, f.context, evidence, original, io);
  assert.equal(proposal.version, 4); assert.equal(proposal.submissionState, 'known-not-submitted');
  const review = { version: 1, action: 'record-exact-private-link-no-submission-without-replay', proposalSha256: hash(proposal),
    sourceSha256: f.source, pendingHeadSha256: hash(proposal.pendingHead), approvedAt: new Date(io.now()).toISOString(),
    expiresAt: new Date(io.now() + 600000).toISOString() };
  const resolution = await recoverPrivateLinkPhase(f.c, f.context, evidence, original, proposal, review, io);
  assert.equal(resolution.version, 2); assert.equal(resolution.externalAdoptionSha256, hash(x.adoption));
  const attemptId = randomUUID(), fixed = privateLinkPhase(f.c, f.context, 'create-environment');
  const continuation = { version: 1, kind: 'reviewed-private-link-no-submission-continuation', attemptId, resolution,
    review: { version: 1, action: 'continue-exact-known-not-submitted-private-link-phase',
      configSha256: hash(f.c), planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin),
      stage: 'create-environment', attemptId, resolutionSha256: hash(resolution), priorIntentSha256: hash(original.intent),
      pendingHeadSha256: hash(proposal.pendingHead), fixedPhaseSha256: hash(fixed), requestSha256: hash(fixed.request),
      sourceSha256: f.source, approvedAt: new Date(io.now()).toISOString(), expiresAt: new Date(io.now() + 600000).toISOString() } };
  const phase = preparePrivateLinkPhase(f.c, f.context, evidence, 'create-environment', null, continuation);
  assert.equal(phase.externalAdoptionSha256, hash(x.adoption));
  assert.deepEqual(phase.request, original.phase.request); assert.equal(phase.version, 2);
  let live = x.current, now = io.now(), journal = null, state = proposal.pendingHead, writes = 0;
  const d = fixed.resources[0], n = f.context.plan.topology.ids;
  const after = privateSnapshotFixture(f, 'create-environment', now);
  for (const [id, value] of Object.entries(live.resources)) if (value && after.resources[id]) {
    if (value.systemData) after.resources[id].systemData = structuredClone(value.systemData);
    if (value.properties?.createdOn) after.resources[id].properties.createdOn = value.properties.createdOn;
  }
  for (const id of [n.vnet, n.appsSubnet, n.endpointSubnet]) after.resources[id] = structuredClone(live.resources[id]);
  after.lists.subnets = structuredClone(live.lists.subnets); after.lists.addressSpaces = structuredClone(live.lists.addressSpaces);
  after.version = 2; after.externalNsg = structuredClone(live.externalNsg);
  for (const nsg of [x.nsg, x.unattachedNsg]) after.lists.groupResources.value.push(live.lists.groupResources.value.find(value => value.id === nsg.id));
  const deployment = { id: fixed.deploymentId, properties: { provisioningState: 'Succeeded', mode: 'Incremental',
    templateHash: hash(fixed.template), correlationId: 'UNIT resumed same fixed request', timestamp: new Date(now).toISOString(),
    outputResources: [{ id: d.id }] } };
  const operations = { value: [{ id: `${fixed.deploymentId}/operations/unit`, operationId: 'unit',
    properties: { provisioningState: 'Succeeded', provisioningOperation: 'Create', statusCode: 'OK',
      targetResource: { id: d.id, resourceType: d.type, resourceName: d.expected.name } } }] };
  const read = io.read;
  const listRequests = privateLinkReadRequests(f.c, f.context);
  const liveIo = { ...io, now: () => now, journal: async () => journal, saveJournal: async value => { journal = structuredClone(value); },
    account: async () => live.accountContext, registry: async () => live.images,
    read: async (request, deadline, paginated) => {
      if (request.id === fixed.deploymentId) return writes ? deployment : null;
      if (request.id === `${fixed.deploymentId}/operations`) return operations;
      if (Object.hasOwn(live.resources, request.id)) return structuredClone(live.resources[request.id]);
      if (Object.hasOwn(live.managed, request.id)) return structuredClone(live.managed[request.id]);
      const list = Object.entries(listRequests).find(([, value]) => value.id === request.id);
      if (list) return structuredClone(live.lists[list[0]]);
      const suffix = '/providers/Microsoft.Insights/diagnosticSettings';
      if (request.id.endsWith(suffix) && Object.hasOwn(live.diagnostics, request.id.slice(0, -suffix.length))) {
        return structuredClone(live.diagnostics[request.id.slice(0, -suffix.length)]);
      }
      if (request.id.endsWith('/permissions')) return { value: [{ actions: ['*'], notActions: [] }] };
      return read(request, deadline, paginated);
    },
    head: async (_e, expected) => { if (expected) assert.deepEqual(state, expected); return state; },
    reserve: async (_e, p, intent) => {
      state = { version: 1, kind: 'private-link-pending-head', targetKey: phase.expectedHead.targetKey,
        previous: phase.expectedHead, intentSha256: hash(intent) }; return state;
    },
    preview: async () => ({ validation: { properties: { provisioningState: 'Succeeded', templateHash: hash(fixed.template) } },
      preview: { status: 'Succeeded', changes: [{ resourceId: d.id, changeType: 'Create', after: { ...d.expected, id: d.id } },
        { resourceId: x.nsg.id, changeType: 'Ignore' }] } }),
    write: async (p, guard, current, mark) => { await current(); const marker = await mark(); guard(); marker.beforeInvoke(); writes++; live = after; },
    append: async (pending, record, next) => { assert.deepEqual(state, pending); state = next; },
  };
  const proof = await checkPrivateLinkPhase(f.c, f.context, evidence, phase, liveIo);
  assert.equal(proof.policy.phaseSha256, hash({ ...phase, resources: [...phase.resources,
    ...[x.nsg, x.unattachedNsg].map(value => ({ id: value.id, type: 'Microsoft.Network/networkSecurityGroups',
      apiVersion: '2024-05-01', expected: value }))] }));
  const approval = { version: 1, action: 'execute-exact-private-link-create-environment', configSha256: hash(f.c),
    planSha256: f.context.plan.planSha256, phaseSha256: hash(phase), bindingSha256: hash(proof.binding),
    sourceSha256: f.source, requestSha256: hash(phase.request), approvedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 600000).toISOString() };
  const invalid = { ...approval, requestSha256: digest('UNIT wider request') };
  await assert.rejects(executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, invalid, liveIo), /EXACT_APPROVAL_REQUIRED/);
  assert.equal(writes, 0); assert.equal(json(original), bytes); assert.equal(json(x.evidence), six);
  const record = await executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, approval, liveIo)
    .catch(error => { console.error('UNIT adopted continuation failure', journal); throw error; });
  verifyPrivateLinkControlEvidence(f.c, f.context, { ...evidence, records: [...evidence.records, record] }, now);
  assert.equal(writes, 1); assert.equal(json(original), bytes); assert.equal(json(x.evidence), six);
  const chain = { ...evidence, records: [...evidence.records, record] }, rf = { ...f, at: now + 1000 };
  let terminalIO;
  for (const stage of STAGES.slice(STAGES.indexOf('disable-storage-public'), STAGES.indexOf('assign-queue-role') + 1)) {
    const q = await privateControlHarness(rf, chain, stage, {
      snapshot: value => adoptedSnapshot(x, value), configureIO: value => adoptedIO(x, value),
    });
    chain.records.push(await q.execute()); rf.at += 1000; terminalIO = q.io;
  }
  const directory = `infrastructure/arm/telemetry/tests/.private-link-nsg-runtime-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  const terminal = chain.records.at(-1), targetKey = privateLinkTargetKey(f.context);
  const canonical = new Map([
    [`private-link-head-${targetKey}.json`, privateLinkHead(f.context, chain)],
    [`private-link-fence-${targetKey}.json`, { version: 1, targetKey, stage: terminal.stage,
      intentSha256: hash(terminal.intent), phase: terminal.phase, intent: terminal.intent }],
    [`private-link-intent-${hash({ target: targetKey, stage: terminal.stage })}.json`, { phase: terminal.phase, intent: terminal.intent }],
    [`private-link-nsg-adoption-${targetKey}.json`, x.adoption],
  ]);
  const options = { now: () => rf.at, sourceDigest: async () => f.source, lookup: async () => f.source,
    store: { root: directory, read: async (_root, name) => structuredClone(canonical.get(name) ?? null) } };
  const current = await currentPrivateLinkRuntimeProof(f.c, f.context, chain, directory,
    retainedReadInvoke(f, terminal.after, terminalIO.read), options);
  assert(current.preservedResourceIds.includes(x.nsg.id)); assert(current.preservedResourceIds.includes(x.unattachedNsg.id));
  assert.equal(current.snapshot.version, 2);
  const changedRead = async (...args) => {
    const value = await terminalIO.read(...args);
    if (args[0].id === x.unattachedNsg.id) value.properties.subnets =
      x.adoption.version === 2 ? [{ id: n.appsSubnet }] : [];
    return value;
  };
  await assert.rejects(currentPrivateLinkRuntimeProof(f.c, f.context, chain, directory,
    retainedReadInvoke(f, terminal.after, changedRead), options), /NSG_RULES_OR_ATTACHMENTS_CHANGED/);
  const prerequisites = verifyPrivateLinkRuntimePrerequisites(f.c, f.context, chain, rf.at);
  const runtime = await privateRuntimeCompletionFixture(rf, structuredClone(chain), prerequisites);
  assert.equal(runtime.completion.controlEvidence.version, 2);
  assert.deepEqual(runtime.completion.controlEvidence.externalAdoption, x.adoption);
  const controlCopies = value => !value || typeof value !== 'object' ? 0 : Object.entries(value).reduce((total, [key, child]) =>
    total + (key === 'controlEvidence' && child?.kind === 'reviewed-private-link-control-chain' ? 1 : 0) + controlCopies(child), 0);
  const sizeReport = { setupEvidenceCompactBytes: Buffer.byteLength(JSON.stringify(chain)),
    runtimeCompletionCompactBytes: Buffer.byteLength(JSON.stringify(runtime.completion)),
    runtimeControlEvidenceCopies: controlCopies(runtime.completion) };
  rf.at = runtime.at + 1000;
  const snapshot = value => {
    adoptedSnapshot(x, value);
    value.resources[n.app] = structuredClone(runtime.completion.disable.observation.app);
    value.images.manifests = structuredClone(runtime.completion.candidate.publication.manifests);
    value.images.queueManifest = JSON.parse(runtime.completion.candidate.profile.manifestJson);
    if (!value.lists.groupResources.value.some(resource => resource.id === n.app)) value.lists.groupResources.value.push(value.resources[n.app]);
    value.lists.apps.value.push(value.resources[n.app]);
  };
  for (const stage of STAGES.slice(STAGES.indexOf('retire-old-receiver'))) {
    const q = await privateControlHarness(rf, chain, stage, {
      runtimeCompletion: runtime.completion, snapshot, configureIO: value => adoptedIO(x, value),
    });
    chain.records.push(await q.execute()); rf.at += 1000;
  }
  assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, chain, rf.at).stage, 'record-migration');
  assert.equal(json(chain.records.slice(0, 6)), json(x.evidence.records));
  assert.equal(json(original), bytes); assert.equal(json(x.evidence), six);
  const bad = structuredClone(chain); bad.externalAdoption.review.userDecision = 'UNIT changed';
  assert.throws(() => verifyPrivateLinkControlEvidence(f.c, f.context, bad, rf.at));
  const artifactStore = createPrivateLinkArtifactStore({ root: directory });
  for (const [name, logical] of [['runtime-completion.json', runtime.completion], ['complete-evidence.json', chain]]) {
    await artifactStore.immutable(directory, name, logical);
    const disk = await load(directory, name);
    assert.equal(disk.kind, 'private-link-artifact-envelope');
    const restored = await artifactStore.load(directory, name);
    assert.equal(hash(restored), hash(logical));
    if (name === 'complete-evidence.json') assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, restored, rf.at).stage, 'record-migration');
  }
  const restored = await artifactStore.load(directory, 'complete-evidence.json');
  assert(Object.isFrozen(restored.records.at(-1).preflight.runtimeCompletion.controlEvidence));
  const final = chain.records.at(-1), prior = { ...chain, records: chain.records.slice(0, -1) };
  const finalPending = { version: 1, kind: 'private-link-pending-head', targetKey,
    previous: privateLinkHead(f.context, prior), intentSha256: hash(final.intent) };
  for (const [name, value] of [
    [`private-link-head-${targetKey}.json`, finalPending],
    [`private-link-fence-${targetKey}.json`, { version: 1, targetKey, stage: final.stage,
      intentSha256: hash(final.intent), phase: final.phase, intent: final.intent }],
    [`private-link-intent-${hash({ target: targetKey, stage: final.stage })}.json`, { phase: final.phase, intent: final.intent }],
    [`private-link-nsg-adoption-${targetKey}.json`, x.adoption],
  ]) await artifactStore.immutable(directory, name, value);
  const appendIO = privateLinkAzureIO(f.c, f.context, prior, final.phase, directory, { publication: final.publication,
    costReview: final.preflight.costReview, costEvidence: final.preflight.costEvidence, migrationReview: final.preflight.migrationReview },
  async () => assert.fail('No cloud invocation in persistence qualification'), {
    now: () => Date.parse(final.completedAt), sourceDigest: async () => f.source,
    store: { root: directory, read: artifactStore.load, save: artifactStore.update, saveImmutable: artifactStore.immutable },
  });
  await appendIO.append(finalPending, final, privateLinkHead(f.context, chain));
  assert.equal(hash(await artifactStore.load(directory, 'private-link-record-migration-record.json')), hash(final));
  assert.equal(hash((await artifactStore.load(directory, `private-link-resolution-${hash(finalPending)}.json`)).record), hash(final));
  assert.deepEqual(await readPrivateLinkHead(f.context, chain, { root: directory, read: artifactStore.load }), privateLinkHead(f.context, chain));
  const persisted = {};
  for (const name of await readdir(directory)) {
    const size = (await stat(resolve(directory, name))).size;
    assert(size <= MAX_PRIVATE_ARTIFACT_BYTES);
    if (name === 'complete-evidence.json' || name === 'runtime-completion.json' ||
        /^private-link-(evidence|candidate)-/u.test(name)) persisted[name] = size;
  }
  t.diagnostic(JSON.stringify({ ...sizeReport, completedEvidenceCompactBytes: Buffer.byteLength(JSON.stringify(chain)),
    completedEvidenceControlCopies: controlCopies(chain), persistedArtifactBytes: persisted }));
}
