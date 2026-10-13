import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { digest, json } from '../definition.mjs';
import { verifyReceiverProfile, verifyReceiverSecurityOverlay, OVERLAY_NATIVE_COVERAGE } from '../receiver-upgrade.mjs';
import { queueUpgradeFixture } from './durable-queue.fixture.mjs';

// Synthetic observations for validation only; no image runtime or source publication is represented.
const f = await queueUpgradeFixture();
const sourceLockJson = await readFile(new URL('../../../../services/telemetry-ingest/runtime-sources.lock.json', import.meta.url), 'utf8');
const lock = JSON.parse(sourceLockJson);
function fixture() {
  const profile = structuredClone(f.candidate.profile);
  const proof = { version: 1, kind: 'observed-debian-openssl-security-overlay',
    manifestDigest: profile.manifestDigest, configDigest: profile.configDigest,
    sourceLockJson, sourceLockSha256: digest(sourceLockJson),
    observedFiles: lock.overlay.files.map(({ path, sha256, size, mode }) => ({ path, sha256, size, mode })),
    maintainerScriptsExecuted: false, nodePatched: false, bundledOpenSSLVersion: '3.5.8' };
  profile.source.files['services/telemetry-ingest/runtime-sources.lock.json'] = proof.sourceLockSha256;
  const qualification = JSON.parse(profile.qualification.reportJson);
  qualification.runtimeSecurityOverlay = proof;
  qualification.nativeCoverage = OVERLAY_NATIVE_COVERAGE;
  qualification.durableQueue.sourceFilesSha256 = digest(json(profile.source.files));
  qualification.durableQueue.sdkSourceManifestSha256 = proof.sourceLockSha256;
  profile.qualification = { reportJson: json(qualification), reportSha256: digest(json(qualification)) };
  return { profile, proof, qualification };
}

test('exact Debian overlay evidence is distinct from unchanged Node native clearance and historical profiles', () => {
  verifyReceiverProfile(f.candidate.profile);
  const { profile, proof } = fixture(), before = json(profile);
  verifyReceiverSecurityOverlay(profile, proof);
  verifyReceiverProfile(profile);
  assert.equal(proof.nodePatched, false);
  assert.equal(profile.priorUnknownGlibcCaveatWaived, false);
  assert.equal(profile.nativeClearance, f.candidate.profile.nativeClearance);
  assert.deepEqual(profile.retainedAdvisories, f.candidate.profile.retainedAdvisories);
  assert.equal(json(profile), before);
});

test('overlay reports cannot replace missing bytes, source binding or native caveats with a clearance flag', () => {
  for (const mutate of [
    x => { x.proof.nodePatched = true; }, x => { x.proof.maintainerScriptsExecuted = true; },
    x => { x.proof.bundledOpenSSLVersion = '3.5.9'; }, x => { x.proof.observedFiles.pop(); },
    x => { x.proof.observedFiles[0].sha256 = digest('wrong native bytes'); },
    x => { x.proof.observedFiles[0].mode = 0o4755; }, x => { x.proof.observedFiles[0].size++; },
    x => { x.proof.observedFiles[0].path = 'usr/bin/unreviewed'; },
    x => { x.proof.observedFiles[1] = x.proof.observedFiles[0]; },
    x => { x.proof.sourceLockJson += ' '; }, x => { x.proof.sourceLockSha256 = digest('other lock'); },
    x => { x.proof.manifestDigest = f.candidate.priorCandidate.profile.manifestDigest; },
    x => { x.profile.priorUnknownGlibcCaveatWaived = true; },
    x => { x.profile.retainedAdvisories = []; },
    x => { x.qualification.nativeCoverage = 'fully patched'; },
    x => { delete x.qualification.runtimeSecurityOverlay; },
  ]) {
    const x = fixture(); mutate(x);
    x.profile.qualification = { reportJson: json(x.qualification), reportSha256: digest(json(x.qualification)) };
    assert.throws(() => verifyReceiverProfile(x.profile));
  }
});

test('bound source locks still require the exact reviewed overlay package and complete file paths', () => {
  for (const mutate of [
    value => { value.schemaVersion = 1; }, value => { value.overlay.method = 'custom-openssl-build'; },
    value => { value.overlay.basePackage.version = 'unverified'; },
    value => { value.overlay.files[0].path = 'usr/bin/unreviewed'; },
    value => { value.packages.find(p => p.name === 'libssl3t64').version = '3.5.7-1~deb13u2'; },
    value => { value.packages.push(value.packages.find(p => p.name === 'libssl3t64')); },
    value => { value.artifacts.find(p => p.filename === value.overlay.artifact).sha256 = digest('other binary'); },
  ]) {
    const x = fixture(), changed = JSON.parse(sourceLockJson); mutate(changed);
    x.proof.sourceLockJson = json(changed);
    x.proof.sourceLockSha256 = digest(x.proof.sourceLockJson);
    x.profile.source.files['services/telemetry-ingest/runtime-sources.lock.json'] = x.proof.sourceLockSha256;
    assert.throws(() => verifyReceiverSecurityOverlay(x.profile, x.proof));
  }
});
