import assert from 'node:assert/strict';
import test from 'node:test';
import { digest, ids, json } from '../definition.mjs';
import { whatIfRequestContext } from '../controller.mjs';
import { privateInput, privateLinkFixture, privateControlChain } from './private-link.fixture.mjs';
import { verifyPrivateLinkRuntimePrerequisites } from '../private-link-controller.mjs';
import { verifyPrivateLinkSnapshot } from '../private-link-readback.mjs';
import { privateLinkRuntimeTarget, oldPublicRuntimeTarget, privateRuntimePhase, verifyPrivateLinkApp } from '../private-link-runtime.mjs';
import { privateRuntimeCompletionFixture } from './private-link-runtime.fixture.mjs';

test('actual plan3 control chain binds patched private and temporary public runtime without old permissions', async () => {
  const f = await privateLinkFixture({ ...structuredClone(privateInput), version: 2 }), evidence = await privateControlChain(f);
  const prerequisites = verifyPrivateLinkRuntimePrerequisites(f.c, f.context, evidence, f.at);
  const target = privateLinkRuntimeTarget(f.c, f.context, f.candidate, prerequisites);
  const old = oldPublicRuntimeTarget(f.c, prerequisites, target);
  assert.equal(evidence.records.length, 13);
  assert.equal(prerequisites.queueResources[f.topology.ids.account].properties.publicNetworkAccess, 'Disabled');
  assert.equal(target.appId, f.context.plan.topology.ids.app);
  assert.equal(target.environmentId, f.context.plan.topology.ids.environment);
  assert.equal(target.privateIp, '10.240.8.68');
  assert.equal(old.appId, ids(f.c).app);
  assert.equal(prerequisites.oldEnvironment.properties.vnetConfiguration, null);
  assert.equal(prerequisites.identity.properties.principalId, f.identity.properties.principalId);
  verifyPrivateLinkApp(f.c, old, f.candidate.priorCandidate, prerequisites.oldApp, {
    [ids(f.c).ingestIdentity]: prerequisites.identity, [ids(f.c).pullIdentity]: prerequisites.pullIdentity,
  }, 'false');
  for (const mutate of [
    value => { value.records.pop(); },
    value => { value.records.at(-1).after.resources[f.topology.ids.account].properties.publicNetworkAccess = 'Enabled'; },
    value => { value.records.at(-1).after.resources[f.topology.ids.assignment].properties.principalId = f.c.operatorPrincipalId; },
  ]) {
    const changed = structuredClone(evidence); mutate(changed);
    assert.throws(() => verifyPrivateLinkRuntimePrerequisites(f.c, f.context, changed, f.at));
  }
  const phase = privateRuntimePhase(f.c, target, '00000000-0000-4000-8000-000000000077', 'disable', prerequisites.controlHeadSha256);
  assert.equal(phase.kind, 'fixed-private-link-runtime-phase');
  assert(phase.request.id.startsWith(ids(f.c).group + '/providers/Microsoft.Resources/deployments/'));
  assert.equal(phase.request.body.properties.template.resources[0].properties.template.containers[0].env
    .find(value => value.name === 'MSR_INGESTION_ENABLED').value, 'false');
  const request = whatIfRequestContext(f.c, phase);
  assert.equal(request.runtimeTargetSha256, digest(json(target)));
  assert.equal(request.scope, 'group');
  assert.equal(request.phase, 'private-link-runtime-disable');
  const escaped = structuredClone(phase);
  escaped.request.body.properties.template.resources[0].name = f.c.namePrefix + '-ingest';
  assert.throws(() => whatIfRequestContext(f.c, escaped), /FIXED_PRIVATE_LINK_RUNTIME_WHATIF_REQUIRED/);
  const { completion } = await privateRuntimeCompletionFixture(f, evidence, prerequisites);
  assert.equal(completion.outcome, 'qualified-private-delivery-disabled');
  assert.deepEqual(completion.controlEvidence, evidence);
  assert.equal(completion.publicProbe.result.storageErrorCode, 'AuthorizationFailure');
  assert.equal(completion.publicProbe.imageDigest, completion.candidate.profile.manifestDigest);
  assert.equal(completion.publicCleanup.absence.app, null);
  const snapshot = structuredClone(evidence.records.at(-1).after), n = f.context.plan.topology.ids;
  snapshot.resources[n.app] = structuredClone(completion.disabled.observation.app);
  snapshot.resources[n.publicProbe] = structuredClone(completion.publicControl.observation.app);
  snapshot.lists.apps.value.push(snapshot.resources[n.app], snapshot.resources[n.publicProbe]);
  snapshot.lists.groupResources.value.push(snapshot.resources[n.app], snapshot.resources[n.publicProbe]);
  snapshot.images.manifests = structuredClone(f.candidate.publication.manifests);
  snapshot.images.queueManifest = JSON.parse(f.candidate.profile.manifestJson);
  verifyPrivateLinkSnapshot(f.c, f.context, snapshot, 'assign-queue-role');
  snapshot.resources[n.publicProbe].properties.template.containers[0].env.find(value => value.name === 'MSR_INGESTION_ENABLED').value = 'true';
  assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, snapshot, 'assign-queue-role'));
  const publicPhase = privateRuntimePhase(f.c, completion.publicTarget, completion.binding.instanceId,
    'create-public-probe', digest(json(completion.disabled)));
  assert.equal(whatIfRequestContext(f.c, publicPhase).phase, 'private-link-runtime-create-public-probe');
  assert.equal(completion.disable.oldApp.id, ids(f.c).app);
});
