import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { LocalWorkflow, openLocalAuthority } from '../dist/api/index.js';
import { createPrivateFixtureRoot, removeFixtureRoot } from './fixtures/windows-private-state.mjs';
import { windowsFileSecurity } from './fixtures/windows-file-security.mjs';

test('actual Windows profile conversion preserves private metadata identity and blocks an old round-trip plan', {
  skip: process.platform !== 'win32', timeout: 180_000,
}, async (t) => {
  const f = createPrivateFixtureRoot();
  t.after(() => removeFixtureRoot(f.root, f.identity));
  const authority = await openLocalAuthority({ directory: f.root, transport: {
    channel: 'trusted-callback', protocolIdentity: { id: 'test.windows-profile', version: '1' },
    confirm: async () => 'accept',
  } });
  const workflow = await LocalWorkflow.open(f.root, { authority });
  const approve = async (plan) => {
    const issued = await authority.confirmPlan(plan);
    assert.equal(issued.status, 'ok');
    assert.equal(issued.value.state, 'issued');
    return issued.value.approval.reference;
  };
  const setup = await workflow.previewSetup();
  await workflow.apply(setup, await approve(setup));
  const creation = await workflow.previewNewChange({ slug: 'profile-test', specs: ['feature'] });
  await workflow.apply(creation, await approve(creation));
  const before = await workflow.loadChange('profile-test');
  const filename = path.join(f.root, before.metadataFile.path);
  const acl = windowsFileSecurity({ path: filename }).fingerprint;
  const preview = await workflow.previewProfileConversion('profile-test', 'compact');
  assert.equal(readFileSync(filename, 'utf8'), before.metadataFile.content);
  const approval = await approve(preview.plan);
  await workflow.commitProfileConversion('profile-test', 'compact', preview.plan, approval);
  const compact = await workflow.loadChange('profile-test');
  assert.equal(compact.metadata.id, before.metadata.id);
  assert.deepEqual(compact.metadata.nodes, before.metadata.nodes);
  assert.equal(compact.metadata.profile, 'compact');
  assert.equal(windowsFileSecurity({ path: filename }).fingerprint, acl);
  const returning = await workflow.previewProfileConversion('profile-test', 'standard');
  await workflow.commitProfileConversion('profile-test', 'standard', returning.plan, await approve(returning.plan));
  const standard = await workflow.loadChange('profile-test');
  assert.equal(standard.metadata.profile, 'standard');
  assert.notEqual(standard.revisions.workflow, before.revisions.workflow);
  assert.deepEqual(standard.metadata.nodes, before.metadata.nodes);
  await assert.rejects(workflow.commitProfileConversion('profile-test', 'compact', preview.plan, approval), { code: 'stale-revision' });
  assert.equal(windowsFileSecurity({ path: filename }).fingerprint, acl);
  assert.deepEqual(await workflow.files.pending(), []);
});
