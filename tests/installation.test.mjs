import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { link, mkdir, readFile, readdir, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { SkillInstallation } from '../dist/application/installation.js';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { makeFilePlan } from '../dist/adapters/filesystem/local-workspace.js';
import { loadPackagedSkillCatalog } from '../dist/adapters/packaged-assets/skills.js';
import {
  INSTALLATION_PATH, SkillCatalog, desiredSkills, parseInstallationRecord, renderSkillSet,
} from '../dist/engines/integration/index.js';
import { digestApprovalRequest, parseApprovalRequest } from '../dist/kernel/authority.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { OPERATION_IDS } from '../dist/kernel/registry.js';

const catalog = await loadPackagedSkillCatalog();
const now = '2026-09-20T12:00:00.000Z';
const hosts = ['copilot', 'codex', 'claude'];

// Fixture authority only: this is not a qualified human or coding-host channel.
function fixtureAuthority() {
  const approvals = new Map();
  return {
    remaining: Infinity,
    issue(request) {
      const value = parseApprovalRequest(request);
      const approval = {
        contractVersion: 1, state: 'trusted-issued', reference: { id: `APR-${randomUUID()}` },
        assurance: { kind: 'local-user', channel: 'qualified-host-callback', qualificationEvidence: digestContent('installation test fixture; no host qualification') },
        request: value, requestDigest: digestApprovalRequest(value), issuedAt: now, expiresAt: '2026-09-21T12:00:00.000Z',
      };
      approvals.set(approval.reference.id, approval);
      return approval.reference;
    },
    async resolve(reference) {
      const approval = approvals.get(reference.id);
      return { status: 'ok', value: this.remaining-- > 0 && approval ? { state: 'current', approval } : { state: 'absent', reference } };
    },
    async requestConfirmation() {
      return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } };
    },
  };
}

async function fixture(t, initialized = true) {
  const root = path.join(process.cwd(), `.installation-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const authority = fixtureAuthority();
  const workflow = await LocalWorkflow.open(root, { authority, now: () => now });
  if (initialized) {
    const setup = await workflow.previewSetup();
    await workflow.apply(setup, authority.issue(setup.request));
  }
  const installation = new SkillInstallation(workflow.files, catalog, '0.0.0');
  return { root, authority, workflow, installation };
}

async function commit(f, preview, installation = f.installation) {
  assert.equal(preview.state, 'ready');
  assert(preview.plan);
  return installation.apply(preview.plan, f.authority.issue(preview.plan.request));
}

async function inventory(root) {
  const result = [];
  async function walk(relative = '') {
    for (const entry of await readdir(path.join(root, relative), { withFileTypes: true })) {
      const file = path.posix.join(relative, entry.name);
      const info = await stat(path.join(root, file), { bigint: true });
      result.push([file, String(info.mtimeNs), entry.isDirectory() ? 'directory' : digestContent(await readFile(path.join(root, file)))]);
      if (entry.isDirectory()) await walk(file);
    }
  }
  await walk();
  return result.sort((left, right) => left[0].localeCompare(right[0]));
}

async function save(root, relative, content) {
  await mkdir(path.dirname(path.join(root, relative)), { recursive: true, mode: 0o700 });
  await writeFile(path.join(root, relative), content, { mode: 0o600 });
}

async function recordAt(f) {
  return JSON.parse(await readFile(path.join(f.root, INSTALLATION_PATH), 'utf8'));
}

test('inspection is no-write even before initialization and does not establish host qualification', async (t) => {
  const f = await fixture(t, false);
  const before = await inventory(f.root);
  const result = await f.installation.inspect();
  assert.equal(result.workspace, null);
  assert.equal(result.ownership, null);
  assert.equal(result.sourceFormat, 'supported');
  assert.equal(result.runtimeQualification, 'not-established');
  assert.equal(result.files.length, 36);
  assert(result.files.every((file) => file.state === 'absent'));
  await assert.rejects(f.installation.previewInstall(['copilot']), { code: 'authority-required' });
  assert.deepEqual(await inventory(f.root), before);
});

test('selected all-host installation previews and writes exactly 36 canonical projections plus ownership', async (t) => {
  const f = await fixture(t);
  await save(f.root, '.github/workflows/keep.yml', 'name: unrelated\n');
  await save(f.root, '.claude/skills/other-consumer/SKILL.md', 'not MissionSpec\n');
  const before = await inventory(f.root);
  const preview = await f.installation.previewInstall(['claude', 'copilot', 'codex']);
  assert.deepEqual(await inventory(f.root), before, 'preview must not write');
  assert.deepEqual(preview.inspection.hosts, hosts);
  assert.equal(preview.changes.length, 37);
  assert.equal(preview.plan.request.operation, 'onboard');
  assert.equal(preview.plan.request.purpose, 'integration');
  for (const change of preview.changes) {
    assert.equal(change.before, null);
    assert.equal(change.beforeDigest, 'absent');
    assert.equal(change.afterDigest, digestContent(change.after));
    assert.match(change.diff, /^--- \/dev\/null\n\+\+\+ b\//u);
  }
  await commit(f, preview);
  for (const skill of renderSkillSet(catalog, hosts, '0.0.0')) {
    assert.equal(await readFile(path.join(f.root, skill.path), 'utf8'), skill.content);
  }
  const record = parseInstallationRecord(await recordAt(f));
  assert.equal(record.files.length, 36);
  assert.deepEqual(record.files, [...desiredSkills(catalog, hosts, '0.0.0')].map((item) => item.ownership).sort((a, b) => a.path.localeCompare(b.path)));
  assert.equal(await readFile(path.join(f.root, '.github/workflows/keep.yml'), 'utf8'), 'name: unrelated\n');
  assert.equal(await readFile(path.join(f.root, '.claude/skills/other-consumer/SKILL.md'), 'utf8'), 'not MissionSpec\n');
  assert((await f.installation.inspect()).files.every((file) => file.state === 'current'));
  assert.equal((await stat(path.join(f.root, INSTALLATION_PATH))).mode & 0o077, 0);
});

test('a selected host gets all twelve skills without writing unselected host trees', async (t) => {
  const f = await fixture(t);
  const preview = await f.installation.previewInstall(['codex']);
  assert.equal(preview.changes.length, 13);
  assert(preview.plan.mutations.every((mutation) => mutation.effect.path === INSTALLATION_PATH || mutation.effect.path.startsWith('.agents/skills/')));
  await commit(f, preview);
  assert.equal((await f.installation.inspect(['codex'])).files.length, 12);
  await assert.rejects(stat(path.join(f.root, '.github')), { code: 'ENOENT' });
  await assert.rejects(stat(path.join(f.root, '.claude')), { code: 'ENOENT' });
});

test('invalid, duplicate, empty and arbitrary host selections fail without writes', async (t) => {
  const f = await fixture(t);
  const before = await inventory(f.root);
  for (const selection of [[], ['copilot', 'copilot'], ['other'], ['../claude'], 'copilot', null]) {
    await assert.rejects(f.installation.previewInstall(selection));
    await assert.rejects(f.installation.inspect(selection));
  }
  assert.deepEqual(await inventory(f.root), before);
});

test('unchanged install/update/remove repeats perform zero writes, including metadata and journals', async (t) => {
  const f = await fixture(t);
  await commit(f, await f.installation.previewInstall(['copilot']));
  const before = await inventory(f.root);
  for (const preview of [
    await f.installation.previewInstall(['copilot']),
    await f.installation.previewUpdate(['copilot']),
    await f.installation.previewRemove(['codex']),
  ]) {
    assert.equal(preview.state, 'unchanged');
    assert.equal(preview.plan, null);
    assert.deepEqual(preview.changes, []);
  }
  await f.installation.inspect();
  assert.deepEqual(await inventory(f.root), before);
});

test('unowned files are conflicts even when their bytes exactly match the renderer', async (t) => {
  const f = await fixture(t);
  const existing = renderSkillSet(catalog, ['copilot'], '0.0.0')[0];
  await save(f.root, existing.path, existing.content);
  const before = await inventory(f.root);
  for (const preview of [
    await f.installation.previewInstall(['copilot']),
    await f.installation.previewUpdate(['copilot']),
    await f.installation.previewRemove(['copilot']),
  ]) {
    assert.equal(preview.state, 'conflicted');
    assert(preview.conflicts.some((conflict) => conflict.path === existing.path && conflict.reason === 'unowned'));
    assert.equal(preview.plan, null);
    assert.deepEqual(preview.changes, []);
  }
  assert.deepEqual(await inventory(f.root), before);
});

test('modified and missing owned files block replacement/removal and retain stale ownership', async (t) => {
  const f = await fixture(t);
  await commit(f, await f.installation.previewInstall(['copilot']));
  const original = await recordAt(f);
  const [modified, missing] = original.files;
  await writeFile(path.join(f.root, modified.path), 'User-maintained instruction content\n');
  await unlink(path.join(f.root, missing.path));
  const before = await inventory(f.root);
  for (const preview of [
    await f.installation.previewInstall(['copilot']),
    await f.installation.previewUpdate(['copilot']),
    await f.installation.previewRemove(['copilot']),
  ]) {
    assert.equal(preview.state, 'conflicted');
    assert(preview.conflicts.some((item) => item.path === modified.path && item.reason === 'modified'));
    assert(preview.conflicts.some((item) => item.path === missing.path && item.reason === 'missing'));
    assert.equal(preview.plan, null);
  }
  assert.deepEqual(await recordAt(f), original);
  assert.deepEqual(await inventory(f.root), before);
});

test('updates are explicit, retain per-host provenance and preserve unselected owned bytes', async (t) => {
  const f = await fixture(t);
  await commit(f, await f.installation.previewInstall(hosts));
  const original = await recordAt(f);
  const newer = new SkillInstallation(f.workflow.files, catalog, '0.0.1');
  const install = await newer.previewInstall(['copilot']);
  assert.equal(install.state, 'conflicted');
  assert(install.conflicts.every((item) => item.reason === 'update-required'));
  const update = await newer.previewUpdate(['copilot']);
  assert.equal(update.changes.length, 13);
  assert(update.changes.every((change) => change.kind === 'update'));
  assert(update.changes.every((change) => change.beforeDigest === digestContent(change.before) && change.afterDigest === digestContent(change.after)));
  await commit(f, update, newer);
  const updated = await recordAt(f);
  for (const file of updated.files) {
    if (file.host === 'copilot') assert.equal(file.generatorVersion, '0.0.1');
    else {
      assert.deepEqual(file, original.files.find((entry) => entry.path === file.path));
      assert.equal(digestContent(await readFile(path.join(f.root, file.path))), file.digest);
    }
  }
  assert((await newer.inspect(['copilot'])).files.every((file) => file.state === 'current'));
  assert((await newer.inspect(['codex'])).files.every((file) => file.state === 'outdated'));
});

test('catalog/body changes update source and template/catalog provenance without adopting absent hosts', async (t) => {
  const f = await fixture(t);
  await commit(f, await f.installation.previewInstall(['claude']));
  const original = await recordAt(f);
  const manifest = await readFile(new URL('../assets/operations/manifest.yaml', import.meta.url), 'utf8');
  const schema = await readFile(new URL('../assets/schemas/operation-manifest.schema.json', import.meta.url), 'utf8');
  const bodies = Object.fromEntries(OPERATION_IDS.map((id) => [id, catalog.body(id)]));
  bodies.discover += '\nOriginal fixture note for an updated source revision.\n';
  const changed = SkillCatalog.parse(manifest, schema, bodies);
  const newer = new SkillInstallation(f.workflow.files, changed, '0.0.0');
  await commit(f, await newer.previewUpdate(['claude']), newer);
  const record = await recordAt(f);
  const previous = original.files.find((file) => file.operation === 'discover');
  const current = record.files.find((file) => file.operation === 'discover');
  assert.notEqual(current.sourceRevision, previous.sourceRevision);
  assert.notEqual(current.catalogRevision, previous.catalogRevision);
  assert.equal(current.templateRevision, previous.templateRevision);
  const absent = await newer.previewUpdate(['codex']);
  assert.equal(absent.state, 'conflicted');
  assert(absent.conflicts.every((conflict) => conflict.reason === 'not-installed'));
});

test('removal deletes only matching owned artifacts and retains other hosts, files and directories', async (t) => {
  const f = await fixture(t);
  await commit(f, await f.installation.previewInstall(hosts));
  await save(f.root, '.github/skills/missionspec-discover/notes.md', 'keep');
  await save(f.root, '.github/skills/unrelated/SKILL.md', 'keep');
  const removal = await f.installation.previewRemove(['copilot']);
  assert.equal(removal.changes.filter((change) => change.kind === 'remove').length, 12);
  assert(removal.changes.filter((change) => change.kind === 'remove').every((change) => change.after === null && change.afterDigest === 'absent'));
  await commit(f, removal);
  assert.equal((await recordAt(f)).files.length, 24);
  assert((await f.installation.inspect(['copilot'])).files.every((file) => file.state === 'absent'));
  assert((await f.installation.inspect(['codex', 'claude'])).files.every((file) => file.state === 'current'));
  assert.equal(await readFile(path.join(f.root, '.github/skills/missionspec-discover/notes.md'), 'utf8'), 'keep');
  assert.equal(await readFile(path.join(f.root, '.github/skills/unrelated/SKILL.md'), 'utf8'), 'keep');
  assert((await stat(path.join(f.root, '.github/skills/missionspec-verify'))).isDirectory());
  await commit(f, await f.installation.previewRemove(['codex', 'claude']));
  assert.deepEqual((await recordAt(f)).files, []);
  const before = await inventory(f.root);
  assert.equal((await f.installation.previewRemove(hosts)).state, 'unchanged');
  assert.deepEqual(await inventory(f.root), before);
});

test('ownership schema rejects unknown owners, duplicate paths, unsafe paths and malformed provenance', async (t) => {
  const f = await fixture(t);
  await commit(f, await f.installation.previewInstall(['copilot']));
  const original = await recordAt(f);
  for (const mutate of [
    (value) => { value.schemaVersion = 2; },
    (value) => { value.owner = 'other-consumer'; },
    (value) => { value.files.push(value.files[0]); },
    (value) => { value.files[0].path = '../../escape'; },
    (value) => { value.files[0].host = 'claude'; },
    (value) => { value.files[0].sourceRevision = 'not-a-digest'; },
    (value) => { value.files[0].generatorVersion = 'arbitrary shell'; },
    (value) => { value.files[0].allow = '*'; },
    (value) => { value.otherConsumer = {}; },
  ]) {
    const invalid = structuredClone(original);
    mutate(invalid);
    assert.throws(() => parseInstallationRecord(invalid));
  }
  const foreign = structuredClone(original);
  foreign.workspace.workspaceId = 'WSP-other-workspace';
  await writeFile(path.join(f.root, INSTALLATION_PATH), JSON.stringify(foreign));
  await assert.rejects(f.installation.inspect(), { code: 'scope-exceeded' });
  assert.deepEqual(await recordAt(f), foreign);
});

test('installation metadata is admitted only in integration-purpose reviewed transactions', async (t) => {
  const f = await fixture(t);
  const preview = await f.installation.previewInstall(['copilot']);
  assert.throws(() => makeFilePlan({
    workspace: preview.plan.workspace, guards: preview.plan.guards, mutations: preview.plan.mutations,
    operation: 'revise', purpose: 'artifact-edit',
  }), /runtime journals and ledgers/u);
  const before = await inventory(f.root);
  await assert.rejects(f.installation.apply(preview.plan, { id: 'APR-not-issued' }), { code: 'authority-required' });
  assert.deepEqual(await inventory(f.root), before);
  const changed = structuredClone(preview.plan);
  changed.mutations[0].content = 'not reviewed';
  await assert.rejects(f.installation.apply(changed, f.authority.issue(preview.plan.request)));
  assert.deepEqual(await inventory(f.root), before);
});

test('bootstrap combines prospective identity and selected skills in one newly reviewed plan', async (t) => {
  const f = await fixture(t, false);
  const setup = await f.workflow.previewSetup();
  const setupApproval = f.authority.issue(setup.request);
  const preview = await f.installation.previewInstall(['copilot'], setup);
  assert.deepEqual(await readdir(f.root), []);
  assert.equal(preview.plan.workspace.workspaceId, setup.workspace.workspaceId);
  await assert.rejects(f.installation.apply(preview.plan, setupApproval), { code: 'scope-exceeded' });
  assert.deepEqual(await readdir(f.root), []);
  await commit(f, preview);
  assert.equal((await f.workflow.project()).state, 'initialized');
  assert.equal((await recordAt(f)).workspace.workspaceId, setup.workspace.workspaceId);
  assert((await f.installation.inspect(['copilot'])).files.every((file) => file.state === 'current'));
});

test('workspace-bound previews and bootstraps cannot be transplanted to another repository', async (t) => {
  const first = await fixture(t);
  const second = await fixture(t);
  const preview = await first.installation.previewInstall(['copilot']);
  const before = await inventory(second.root);
  await assert.rejects(second.installation.apply(preview.plan, second.authority.issue(preview.plan.request)), { code: 'scope-exceeded' });
  assert.deepEqual(await inventory(second.root), before);
  const fresh = await fixture(t, false);
  const other = await fixture(t, false);
  await assert.rejects(fresh.installation.previewInstall(['copilot'], await other.workflow.previewSetup()), { code: 'scope-exceeded' });
  assert.deepEqual(await readdir(fresh.root), []);
});

test('even newly confirmed file plans cannot use installation to publish noncanonical skill content', async (t) => {
  const f = await fixture(t);
  const preview = await f.installation.previewInstall(['copilot']);
  const mutations = structuredClone(preview.plan.mutations);
  const first = mutations.find((mutation) => mutation.effect.path.endsWith('/SKILL.md'));
  first.content = 'Not generated by the canonical renderer.\n';
  first.effect.proposed = digestContent(first.content);
  const forged = makeFilePlan({
    workspace: preview.plan.workspace, guards: preview.plan.guards, mutations,
    operation: 'onboard', purpose: 'integration',
  });
  const before = await inventory(f.root);
  await assert.rejects(f.installation.apply(forged, f.authority.issue(forged.request)), { code: 'scope-exceeded' });
  assert.deepEqual(await inventory(f.root), before);
});

test('stale files and ownership changes after preview reject before installed file writes', async (t) => {
  const f = await fixture(t);
  const preview = await f.installation.previewInstall(['copilot']);
  const skill = preview.changes.find((change) => change.path.endsWith('/SKILL.md'));
  await save(f.root, skill.path, 'concurrent owner\n');
  const before = await inventory(f.root);
  await assert.rejects(commit(f, preview), { code: 'stale-revision' });
  assert.deepEqual(await inventory(f.root), before);
  await unlink(path.join(f.root, skill.path));
  await commit(f, await f.installation.previewInstall(['copilot']));
  const remove = await f.installation.previewRemove(['copilot']);
  const record = await recordAt(f);
  record.files[0].catalogRevision = digestContent('changed record');
  await writeFile(path.join(f.root, INSTALLATION_PATH), JSON.stringify(record));
  const changed = await inventory(f.root);
  await assert.rejects(commit(f, remove), { code: 'stale-revision' });
  assert.deepEqual(await inventory(f.root), changed);
});

test('interrupted installs remain journaled and resume only through reviewed recovery', async (t) => {
  const f = await fixture(t);
  const preview = await f.installation.previewInstall(['copilot']);
  f.authority.remaining = 2;
  await assert.rejects(commit(f, preview), { code: 'effect-outcome-unknown' });
  const pending = await f.workflow.files.pending();
  assert.equal(pending.length, 1);
  assert.equal((await f.installation.inspect(['copilot'])).pendingTransactions.length, 1);
  await assert.rejects(f.installation.previewInstall(['copilot']), { code: 'conflict' });
  f.authority.remaining = Infinity;
  const recovery = await f.workflow.files.recoveryPlan(pending[0]);
  await f.workflow.files.recover(pending[0], f.authority.issue(recovery.request));
  assert.deepEqual(await f.workflow.files.pending(), []);
  assert((await f.installation.inspect(['copilot'])).files.every((file) => file.state === 'current'));
  assert.equal((await f.installation.previewInstall(['copilot'])).state, 'unchanged');
});

test('recovery preserves edits made after a partial install rather than replaying over them', async (t) => {
  const f = await fixture(t);
  const preview = await f.installation.previewInstall(['copilot']);
  f.authority.remaining = 2;
  await assert.rejects(commit(f, preview), { code: 'effect-outcome-unknown' });
  const [pending] = await f.workflow.files.pending();
  const first = preview.plan.mutations[0].effect.path;
  await writeFile(path.join(f.root, first), 'user changed partial output\n');
  f.authority.remaining = Infinity;
  await assert.rejects(f.workflow.files.recoveryPlan(pending), { code: 'stale-revision' });
  assert.equal(await readFile(path.join(f.root, first), 'utf8'), 'user changed partial output\n');
  assert.deepEqual(await f.workflow.files.pending(), [pending]);
});

test('symlinked host parents, skill targets and ownership paths are rejected without external writes', async (t) => {
  for (const target of ['parent', 'skill', 'metadata']) {
    const f = await fixture(t);
    const external = path.join(f.root, 'external');
    await mkdir(external, { mode: 0o700 });
    if (target === 'parent') await symlink(external, path.join(f.root, '.github'), 'dir');
    else {
      await writeFile(path.join(external, 'target'), 'untouched\n', { mode: 0o600 });
      const relative = target === 'skill' ? renderSkillSet(catalog, ['copilot'], '0.0.0')[0].path : INSTALLATION_PATH;
      await mkdir(path.dirname(path.join(f.root, relative)), { recursive: true, mode: 0o700 });
      await symlink(path.join(external, 'target'), path.join(f.root, relative));
    }
    await assert.rejects(f.installation.previewInstall(['copilot']), { code: 'scope-exceeded' });
    if (target === 'parent') assert.deepEqual(await readdir(external), []);
    else assert.equal(await readFile(path.join(external, 'target'), 'utf8'), 'untouched\n');
  }
});

test('hard-linked projection targets are rejected instead of being claimed', async (t) => {
  const f = await fixture(t);
  const relative = renderSkillSet(catalog, ['copilot'], '0.0.0')[0].path;
  await save(f.root, 'original', 'untouched\n');
  await mkdir(path.dirname(path.join(f.root, relative)), { recursive: true, mode: 0o700 });
  await link(path.join(f.root, 'original'), path.join(f.root, relative));
  await assert.rejects(f.installation.previewInstall(['copilot']), { code: 'scope-exceeded' });
  assert.equal(await readFile(path.join(f.root, 'original'), 'utf8'), 'untouched\n');
});
