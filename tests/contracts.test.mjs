import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CONTRACT_VERSION,
  ContractError,
  ENGINE_IDS,
  ENGINES,
  ID_PREFIXES,
  NATIVE_HOSTS,
  OPERATION_IDS,
  OPERATIONS,
  digestApprovalRequest,
  digestContent,
  digestEffectScope,
  getOperation,
  parseApprovalReference,
  parseApprovalRequest,
  parseChangeSlug,
  parseContractVersion,
  parseDigest,
  parseDomainError,
  parseEffectScope,
  parseEngineId,
  parseExecutionLimits,
  parseExecutionMode,
  parseExecutionRequest,
  parseId,
  parseNativeHost,
  parseOperationId,
  parseProjectPath,
  parseRequestedEffect,
  parseReviewBinding,
  parseRevisionBinding,
  parseWorkspaceBinding,
  sameRevisionBinding,
  sameWorkspaceBinding,
} from '../dist/kernel/index.js';
import {
  DEFAULT_WORKFLOW_PROFILE,
  STANDARD_ARTIFACT_NODES,
  captureArtifactSnapshot,
  parseArtifactNodeId,
} from '../dist/engines/specification/contracts.js';
import {
  orderTaskDefinitions,
  parsePlannedCheck,
  parseTaskDefinition,
} from '../dist/engines/planning/contracts.js';

const digest = digestContent('reviewed content');
const workspace = { workspaceId: 'WSP-local', rootDigest: digestContent('observed local workspace root') };
const effects = [{ kind: 'host-dispatch', host: 'copilot', taskIds: ['TSK-first'] }];

function revisions(effectScope = effects) {
  return {
    workspace,
    changeId: 'CHG-login',
    specification: digest,
    tasks: digest,
    workflow: digest,
    effects: digestEffectScope(effectScope),
    source: digest,
  };
}

function approvalRequest() {
  return {
    contractVersion: CONTRACT_VERSION,
    state: 'untrusted-request',
    purpose: 'execution',
    operation: 'implement',
    binding: { kind: 'change', revisions: revisions() },
    effects,
    execution: {
      host: 'copilot',
      limits: { maxTasks: 1, maxDurationMs: 60_000, maxRepairsPerTask: 2, concurrency: 1 },
    },
  };
}

function task(id, dependsOn = []) {
  return {
    contractVersion: CONTRACT_VERSION,
    id,
    title: 'Implement the scoped change',
    dependsOn,
    requirements: ['REQ-login'],
    scenarios: ['SCN-login'],
    checks: ['CHK-login'],
    writeScope: ['src/login.ts'],
  };
}

test('closed protocol and native host identifiers reject guessed or coerced values', () => {
  assert.equal(parseContractVersion(1), 1);
  for (const bad of [0, 2, '1', true, null, undefined, NaN, Infinity]) {
    assert.throws(() => parseContractVersion(bad), ContractError);
  }
  assert.deepEqual(NATIVE_HOSTS, ['copilot', 'codex', 'claude']);
  for (const host of NATIVE_HOSTS) assert.equal(parseNativeHost(host), host);
  for (const bad of ['Copilot', 'claude-code', 'terminal', '', '__proto__', null]) {
    assert.throws(() => parseNativeHost(bad), ContractError);
  }
});

test('all stable identity kinds validate prefixes without silently normalizing', () => {
  for (const [kind, prefix] of Object.entries(ID_PREFIXES)) {
    assert.equal(parseId(kind, `${prefix}-login-01`), `${prefix}-login-01`);
    for (const bad of [`${prefix}-`, `${prefix}-a_b`, `${prefix}-a--b`, `${prefix}-../other`, ` ${prefix}-a`, true]) {
      assert.throws(() => parseId(kind, bad), ContractError);
    }
  }
  assert.throws(() => parseId('requirement', 'TSK-login'), ContractError);
  assert.throws(() => parseId('unknown', 'REQ-login'), ContractError);
  assert.throws(() => parseId('task', `TSK-${'a'.repeat(80)}`), ContractError);
});

test('change slugs are flat labels and cannot collide with reserved archive or device names', () => {
  for (const slug of ['login', 'passkey-auth-2', '2026-09-login']) {
    assert.equal(parseChangeSlug(slug), slug);
  }
  for (const bad of ['', '.', '..', 'a/b', 'a\\b', '/root', 'C:drive', 'archive', 'con', 'nul', 'com1', 'lpt9', 'UPPER', '-a', 'a-', 'a--b', '%2e%2e', 'a ']) {
    assert.throws(() => parseChangeSlug(bad), ContractError);
  }
});

test('portable paths reject traversal, absolute paths, encodings, glob syntax and Windows aliases', () => {
  for (const path of ['missionspec/changes/login/tasks.md', '.missionspec/state/ledger.sqlite', 'docs/with spaces.md', 'src/café.ts']) {
    assert.equal(parseProjectPath(path), path);
  }
  for (const bad of ['', '.', '..', '../file', 'a/../file', 'a/./file', '/etc/passwd', '//host/share', 'C:/file', 'C:\\file', 'a\\b', 'a//b', 'a/', 'CON', 'a/nul.txt', 'a/com1.log', 'a/file.', 'a/file ', 'a/%2e%2e/file', 'a/*', 'a/?', 'a/\u0000b', 'a/\nb']) {
    assert.throws(() => parseProjectPath(bad), ContractError);
  }
});

test('registries cover exactly twelve default skills and six functional owners', () => {
  assert.deepEqual(OPERATION_IDS, ['discover', 'draft', 'draft-all', 'implement', 'verify', 'archive', 'revise', 'clarify', 'analyze', 'principles', 'sync', 'onboard']);
  assert.deepEqual(ENGINE_IDS, ['discovery', 'specification', 'planning', 'execution', 'verification', 'integration']);
  assert.equal(ENGINES.length, 6);
  assert.equal(Object.keys(OPERATIONS).length, 12);
  assert.equal(Object.values(OPERATIONS).filter((operation) => operation.class === 'primary').length, 6);
  for (const id of OPERATION_IDS) {
    const operation = getOperation(id);
    assert.equal(operation.id, id);
    assert.equal(operation.nativeName, `missionspec-${id}`);
    assert.equal(operation.installedByDefault, true);
    assert.ok(Object.isFrozen(operation));
    assert.ok(Object.isFrozen(operation.engines));
    for (const engine of operation.engines) {
      assert.ok(ENGINES.find((item) => item.id === engine).operations.includes(id));
    }
  }
  assert.equal(OPERATIONS.draft.stop, 'one-ready-artifact');
  assert.equal(OPERATIONS['draft-all'].stop, 'required-drafts-or-review-blocker');
  assert.equal(OPERATIONS.verify.stop, 'evidence-and-gaps');
  assert.equal(OPERATIONS.sync.stop, 'confirmed-promotion-change-open');
  assert.equal(OPERATIONS.analyze.defaultAccess, 'read-only');
  assert.deepEqual(OPERATIONS.clarify.engines, ['discovery', 'specification']);
  for (const bad of ['propose', 'prepare', 'ff', 'managed', '__proto__', null]) {
    assert.throws(() => parseOperationId(bad), ContractError);
  }
  assert.equal(parseEngineId('execution'), 'execution');
  assert.throws(() => parseEngineId('context'), ContractError);
  assert.throws(() => { OPERATIONS.draft.engines.push('execution'); }, TypeError);
});

test('content digests bind exact bytes and revision equality checks every dimension', () => {
  assert.equal(digestContent('abc'), 'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(digestContent(new TextEncoder().encode('abc')), digestContent('abc'));
  assert.notEqual(digestContent('abc\n'), digestContent('abc'));
  assert.equal(parseDigest(digest), digest);
  for (const bad of ['abc', digest.toUpperCase(), `sha256:${'0'.repeat(63)}`, null]) {
    assert.throws(() => parseDigest(bad), ContractError);
  }
  assert.throws(() => digestContent(123), ContractError);
  const binding = parseRevisionBinding(revisions());
  assert.ok(Object.isFrozen(binding));
  assert.equal(sameRevisionBinding(binding, { ...binding }), true);
  for (const key of ['specification', 'tasks', 'workflow', 'effects', 'source']) {
    assert.equal(sameRevisionBinding(binding, { ...binding, [key]: digestContent('changed') }), false);
  }
  assert.equal(sameRevisionBinding(binding, { ...binding, changeId: 'CHG-other' }), false);
  assert.equal(sameRevisionBinding(binding, {
    ...binding, workspace: { ...workspace, workspaceId: 'WSP-other' },
  }), false);
  assert.equal(sameRevisionBinding(binding, {
    ...binding, workspace: { ...workspace, rootDigest: digestContent('other root') },
  }), false);
  assert.throws(() => parseRevisionBinding({ ...binding, approved: true }), ContractError);
  assert.throws(() => parseReviewBinding({ kind: 'change', revisions: binding, revision: digest }), ContractError);
  assert.throws(() => parseReviewBinding({ kind: 'unknown' }), ContractError);
});

test('effect requests are exact, immutable and revision-bound rather than wildcard grants', () => {
  const scope = parseEffectScope([
    { kind: 'file-write', purpose: 'artifact', path: 'missionspec/changes/login/tasks.md', expected: 'absent', proposed: digest },
    { kind: 'file-remove', purpose: 'closure', path: 'missionspec/changes/login/design.md', expected: digest },
    { kind: 'check-execute', checkId: 'CHK-login', definition: digest },
    ...effects,
    { kind: 'context-consume', providerId: 'CTX-local', paths: ['src/login.ts'], allowRemoteProcessing: false },
  ]);
  assert.ok(Object.isFrozen(scope));
  assert.ok(scope.every(Object.isFrozen));
  assert.notEqual(digestEffectScope(scope), digestEffectScope([...scope].reverse()));
  assert.throws(() => parseEffectScope([scope[0], scope[0]]), ContractError);
  assert.throws(() => parseEffectScope([scope[0], { kind: 'file-remove', purpose: 'artifact', path: scope[0].path, expected: digest }]), ContractError);
  for (const invalid of [
    { kind: 'shell', command: 'echo unscoped' },
    { ...scope[0], path: '../escape' },
    { ...scope[0], before: digest },
    { ...scope[1], expected: 'absent' },
    { ...effects[0], taskIds: ['TSK-first', 'TSK-first'] },
    { ...effects[0], taskIds: [] },
    { ...scope[4], allowRemoteProcessing: 'false' },
  ]) {
    assert.throws(() => parseRequestedEffect(invalid), ContractError);
  }
});

test('Interactive is default; Auto is explicit and all run bounds are required', () => {
  assert.equal(parseExecutionMode(), 'interactive');
  assert.equal(parseExecutionMode('auto'), 'auto');
  for (const bad of ['Auto', 'managed', true, null]) assert.throws(() => parseExecutionMode(bad), ContractError);
  const limits = approvalRequest().execution.limits;
  assert.deepEqual(parseExecutionLimits(limits), limits);
  const { concurrency: _serialDefault, ...withoutConcurrency } = limits;
  assert.equal(parseExecutionLimits(withoutConcurrency).concurrency, 1);
  for (const repairCount of [0, 1, 2]) {
    assert.equal(parseExecutionLimits({ ...limits, maxRepairsPerTask: repairCount }).maxRepairsPerTask, repairCount);
  }
  for (const invalid of [
    { ...limits, maxTasks: 0 }, { ...limits, maxDurationMs: Infinity },
    { ...limits, maxDurationMs: 1.1 }, { ...limits, concurrency: 2 },
    { ...limits, maxRepairsPerTask: 3 }, { ...limits, maxRepairsPerTask: -1 },
    { maxTasks: 1 }, { ...limits, tokenHardCap: 1000 },
  ]) assert.throws(() => parseExecutionLimits(invalid), ContractError);
  assert.equal(parseExecutionRequest(approvalRequest().execution).mode, 'interactive');
  assert.throws(() => parseExecutionRequest({ host: 'codex', limits: true }), ContractError);
});

test('public approval parsing never issues trusted authority from text, booleans or records', () => {
  const request = parseApprovalRequest(approvalRequest());
  assert.equal(request.state, 'untrusted-request');
  assert.equal(request.execution.mode, 'interactive');
  assert.ok(Object.isFrozen(request.binding.revisions));
  assert.ok(Object.isFrozen(request.execution.limits));
  assert.equal(digestApprovalRequest(request), digestApprovalRequest(parseApprovalRequest(approvalRequest())));
  const mutations = [
    { ...approvalRequest(), state: 'trusted-issued' },
    { ...approvalRequest(), approved: true },
    { ...approvalRequest(), contractVersion: 2 },
    { ...approvalRequest(), purpose: 'acceptance' },
    { ...approvalRequest(), binding: { kind: 'project', workspace, revision: digest, effects: digestEffectScope(effects) } },
    { ...approvalRequest(), effects: [] },
    { ...approvalRequest(), execution: { ...approvalRequest().execution, host: 'codex' } },
    { ...approvalRequest(), operation: 'verify' },
  ];
  for (const invalid of [true, 'User says approved', ...mutations]) {
    assert.throws(() => parseApprovalRequest(invalid), ContractError);
  }
  assert.deepEqual(parseApprovalReference({ id: 'APR-local-1' }), { id: 'APR-local-1' });
  assert.throws(() => parseApprovalReference({ id: 'APR-local-1', trusted: true }), ContractError);
  assert.throws(() => parseApprovalReference({ id: 'REQ-local-1' }), ContractError);
});

test('project document requests can be bound without inventing a change or an execution grant', () => {
  const request = {
    contractVersion: 1,
    state: 'untrusted-request',
    purpose: 'artifact-edit',
    operation: 'principles',
    binding: { kind: 'project', workspace, revision: digest, effects: digestEffectScope([]) },
    effects: [],
  };
  assert.equal(parseApprovalRequest(request).binding.kind, 'project');
  assert.throws(() => parseApprovalRequest({ ...request, execution: undefined }), ContractError);
  assert.throws(() => parseApprovalRequest({ ...request, binding: { ...request.binding, effects: digest } }), ContractError);
});

test('workspace scope is mandatory and changes approval identity independently of content', () => {
  assert.deepEqual(parseWorkspaceBinding(workspace), workspace);
  assert.equal(sameWorkspaceBinding(workspace, { ...workspace }), true);
  assert.throws(() => parseWorkspaceBinding({ workspaceId: 'CHG-local', rootDigest: digest }), ContractError);
  assert.throws(() => parseWorkspaceBinding({ ...workspace, approved: true }), ContractError);
  const missing = revisions();
  delete missing.workspace;
  assert.throws(() => parseRevisionBinding(missing), ContractError);
  assert.throws(() => parseReviewBinding({ kind: 'project', revision: digest, effects: digest }), ContractError);
  const original = approvalRequest();
  const copied = structuredClone(original);
  copied.binding.revisions.workspace.workspaceId = 'WSP-other';
  assert.notEqual(digestApprovalRequest(original), digestApprovalRequest(copied));
  const relocated = structuredClone(original);
  relocated.binding.revisions.workspace.rootDigest = digestContent('relocated root');
  assert.notEqual(digestApprovalRequest(original), digestApprovalRequest(relocated));
});

test('data validators reject getters, class instances, inherited payloads and sparse arrays', () => {
  assert.throws(() => parseApprovalReference({ get id() { throw new Error('must not run'); } }), ContractError);
  assert.throws(() => parseApprovalReference(new Date()), ContractError);
  assert.throws(() => parseApprovalReference(Object.create({ id: 'APR-one' })), ContractError);
  const sparse = Array(1);
  assert.throws(() => parseEffectScope(sparse), ContractError);
  assert.throws(() => parseApprovalReference({ id: 'APR-one', [Symbol('hidden')]: true }), ContractError);
});

test('artifact snapshots preserve a multi-file specs node and compute a stable detached revision', () => {
  const input = {
    contractVersion: 1,
    id: 'ART-specs',
    node: 'specs',
    files: [
      { path: 'missionspec/changes/login/specs/login/spec.md', content: '# Login\n' },
      { path: 'missionspec/changes/login/specs/accounts/spec.md', content: '# Accounts\n' },
    ],
    dependencies: [{ artifactId: 'ART-proposal', revision: digest }],
  };
  const snapshot = captureArtifactSnapshot(input);
  assert.equal(snapshot.files.length, 2);
  assert.equal(snapshot.node, 'specs');
  assert.equal(Object.hasOwn(snapshot, 'ready'), false);
  assert.equal(Object.hasOwn(snapshot, 'approved'), false);
  assert.equal(snapshot.revision, captureArtifactSnapshot({ ...input, files: [...input.files].reverse() }).revision);
  input.files[0].content = '# Changed\n';
  assert.equal(snapshot.files[0].content, '# Login\n');
  assert.notEqual(snapshot.revision, captureArtifactSnapshot(input).revision);
  assert.ok(Object.isFrozen(snapshot.files[0]));
  assert.equal(DEFAULT_WORKFLOW_PROFILE, 'standard');
  assert.deepEqual(STANDARD_ARTIFACT_NODES, ['proposal', 'specs', 'design', 'tasks']);
  assert.equal(parseArtifactNodeId('custom-review'), 'custom-review');
  for (const invalid of [
    { ...input, files: [] },
    { ...input, files: [input.files[0], input.files[0]] },
    { ...input, files: [{ path: '../outside.md', content: '# No' }] },
    { ...input, dependencies: [{ artifactId: 'ART-specs', revision: digest }] },
    { ...input, node: '../tasks' },
    { ...input, contractVersion: 99 },
    { ...input, approved: true },
  ]) assert.throws(() => captureArtifactSnapshot(invalid), ContractError);
});

test('task definitions retain traceability but never treat completion booleans as runtime facts', () => {
  const input = task('TSK-login');
  const parsed = parseTaskDefinition(input);
  input.requirements.push('REQ-new');
  assert.deepEqual(parsed.requirements, ['REQ-login']);
  assert.ok(Object.isFrozen(parsed.requirements));
  for (const invalid of [
    { ...task('TSK-login'), completed: true },
    { ...task('TSK-login'), approved: true },
    { ...task('TSK-login'), dependsOn: ['TSK-login'] },
    { ...task('TSK-login'), checks: ['REQ-login'] },
    { ...task('TSK-login'), writeScope: ['src/**'] },
    { ...task('TSK-login'), requirements: ['REQ-login', 'REQ-login'] },
  ]) assert.throws(() => parseTaskDefinition(invalid), ContractError);
});

test('task ordering rejects missing identities and cycles and orders shared dependency graphs', () => {
  const ordered = orderTaskDefinitions([
    task('TSK-last', ['TSK-left', 'TSK-right']),
    task('TSK-left', ['TSK-first']),
    task('TSK-right', ['TSK-first']),
    task('TSK-first'),
  ]);
  assert.deepEqual(ordered.map(({ id }) => id), ['TSK-first', 'TSK-left', 'TSK-right', 'TSK-last']);
  assert.ok(Object.isFrozen(ordered));
  assert.deepEqual(orderTaskDefinitions([]), []);
  for (const invalid of [
    [task('TSK-a'), task('TSK-a')],
    [task('TSK-a', ['TSK-missing'])],
    [task('TSK-a', ['TSK-b']), task('TSK-b', ['TSK-a'])],
    [task('TSK-a', ['TSK-b']), task('TSK-b', ['TSK-c']), task('TSK-c', ['TSK-a'])],
  ]) assert.throws(() => orderTaskDefinitions(invalid), ContractError);
});

test('planned checks are definitions, not fabricated observations or acceptance', () => {
  const input = {
    contractVersion: 1, id: 'CHK-login', kind: 'executed', description: 'Run scoped login tests',
    definition: digest, requirements: ['REQ-login'], scenarios: ['SCN-login'],
  };
  const check = parsePlannedCheck(input);
  assert.equal(check.kind, 'executed');
  assert.equal(Object.hasOwn(check, 'passed'), false);
  for (const invalid of [
    { ...input, passed: true }, { ...input, kind: 'approved' }, { ...input, definition: 'HEAD' },
  ]) assert.throws(() => parsePlannedCheck(invalid), ContractError);
});

test('structured errors have closed codes and explicit retry policy without raw exception fields', () => {
  const input = { code: 'stale-revision', message: 'Review the changed source revision.', retry: 'after-review', fields: ['source'] };
  const error = parseDomainError(input);
  assert.deepEqual(error, input);
  assert.ok(Object.isFrozen(error.fields));
  for (const invalid of [
    { ...input, code: 'arbitrary' }, { ...input, retry: true }, { ...input, stack: 'private data' },
  ]) assert.throws(() => parseDomainError(invalid), ContractError);
});
