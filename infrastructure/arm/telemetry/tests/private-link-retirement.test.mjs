import assert from 'node:assert/strict';
import test from 'node:test';
import { ids, json } from '../definition.mjs';
import { PRIVATE_LINK_CONTROL_STAGES as STAGES } from '../private-link.mjs';
import { verifyPrivateLinkControlEvidence, verifyPrivateLinkRuntimePrerequisites } from '../private-link-controller.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateControlHarness } from './private-link.fixture.mjs';
import { privateRuntimeCompletionFixture } from './private-link-runtime.fixture.mjs';

const base = await privateLinkFixture({ ...privateInput, version: 2 });
const chain = await privateControlChain({ ...base });
const at = Date.parse(chain.records.at(-1).completedAt) + 1000;

test('real control evidence plus genuine runtime verifier permits exact old retirement and append-only completion', async () => {
  const evidence = { ...chain, records: [...chain.records] }, rf = { ...base, at };
  const prerequisites = verifyPrivateLinkRuntimePrerequisites(base.c, base.context, evidence, rf.at);
  const runtime = await privateRuntimeCompletionFixture(rf, structuredClone(evidence), prerequisites);
  rf.at = runtime.at + 1000;
  const n = base.context.plan.topology.ids, originalBytes = json(base.context.origin.original);
  const snapshot = state => {
    state.resources[n.app] = structuredClone(runtime.completion.disable.observation.app);
    state.images.manifests = structuredClone(runtime.completion.candidate.publication.manifests);
    state.images.queueManifest = JSON.parse(runtime.completion.candidate.profile.manifestJson);
    if (!state.lists.groupResources.value.some(value => value.id === n.app)) state.lists.groupResources.value.push(state.resources[n.app]);
    state.lists.apps.value.push(state.resources[n.app]);
  };
  for (const stage of STAGES.slice(STAGES.indexOf('retire-old-receiver'))) {
    const q = await privateControlHarness(rf, evidence, stage, { runtimeCompletion: runtime.completion, snapshot });
    const record = await q.execute().catch(error => { console.error('UNIT retirement failure', stage, q.journal); throw error; });
    assert.equal(q.writes, stage === 'record-migration' ? 0 : 1);
    evidence.records.push(record); rf.at += 1000;
  }
  const completed = verifyPrivateLinkControlEvidence(base.c, base.context, evidence, rf.at);
  assert.equal(completed.stage, 'record-migration');
  assert.equal(completed.after.resources[n.oldApp], null);
  assert.equal(completed.after.resources[n.oldEnvironment], null);
  assert.equal(completed.after.resources[ids(base.c).projectBudget].properties.amount, 375);
  assert.equal(completed.after.resources[ids(base.c).budget].properties.amount, 325);
  assert.equal(completed.after.resources[n.app].properties.template.containers[0].env.find(value => value.name === 'MSR_INGESTION_ENABLED').value, 'false');
  assert.equal(completed.preflight.runtimeCompletion.publicProbe.result.metadataStatus, 403);
  assert.equal(completed.preflight.runtimeCompletion.probe.result.metadataStatus, 200);
  assert.equal(json(base.context.origin.original), originalBytes);
  const bad = structuredClone(completed);
  bad.preflight.runtimeCompletion.publicProbe.result.storageErrorCode = 'AuthenticationFailed';
  assert.throws(() => verifyPrivateLinkControlEvidence(base.c, base.context, {
    ...evidence, records: [...evidence.records.slice(0, -1), bad],
  }));
});
