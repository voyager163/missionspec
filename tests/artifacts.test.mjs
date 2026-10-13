import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { stringify } from 'yaml';
import { ContractError, digestContent } from '../dist/kernel/index.js';
import {
  captureArtifactSnapshot, parseMarkdownDocument, parseMarkdownSet,
} from '../dist/engines/specification/contracts.js';
import {
  artifactDependencyClosure, assessArtifactReadiness, notApplicableArtifactRevision,
  parseArtifactWorkflow, parseWorkflowProfile,
} from '../dist/engines/planning/contracts.js';

const standardWorkflow = await readFile(new URL('../assets/workflows/standard/workflow.yaml', import.meta.url), 'utf8');
const compactWorkflow = await readFile(new URL('../assets/workflows/compact/workflow.yaml', import.meta.url), 'utf8');
const exampleFiles = {
  standard: ['proposal.md', 'specs/filters.md', 'specs/reset.md', 'design.md', 'tasks.md'],
  compact: ['proposal.md', 'specs/summary.md', 'tasks.md'],
};
const examples = {};
for (const profile of ['standard', 'compact']) {
  examples[profile] = Object.fromEntries(await Promise.all(exampleFiles[profile].map(async (path) => [
    path, await readFile(new URL(`../assets/workflows/${profile}/examples/${path}`, import.meta.url), 'utf8'),
  ])));
}

const sourceRevision = digestContent('a supplied source snapshot');
const pathFor = (relative) => `missionspec/changes/example/${relative}`;
const sources = (profile = 'standard') => Object.entries(examples[profile]).map(([path, content]) => ({
  path: pathFor(path), content,
}));
const parseExample = (name, content = examples.standard[name]) => parseMarkdownDocument({ path: pathFor(name), content });
const codes = (result) => result.diagnostics.map((entry) => entry.code);

function snapshot(node, files, dependencies = []) {
  return captureArtifactSnapshot({
    contractVersion: 1, id: `ART-${node}`, node, files,
    dependencies: dependencies.map(([artifact, revision]) => ({ artifactId: `ART-${artifact}`, revision })),
  });
}

function fixture(profile = 'standard', skipDesign = profile === 'compact') {
  const workflowSource = profile === 'standard' ? standardWorkflow : compactWorkflow;
  const expectedWorkflow = digestContent(workflowSource);
  const applicable = { state: 'required' };
  const skipped = {
    state: 'not-applicable', reason: 'The scoped approach is recorded in tasks; no separate design is needed.',
    sourceRevision, dependencies: [],
  };
  const byNode = {
    proposal: ['proposal.md'],
    specs: exampleFiles[profile].filter((path) => path.startsWith('specs/')),
    design: ['design.md'],
    tasks: ['tasks.md'],
  };
  const bindings = ['proposal', 'specs', 'design', 'tasks'].map((node) => ({
    node, artifactId: `ART-${node}`, declaredOutputs: byNode[node].map(pathFor),
    applicability: node === 'design' && skipDesign ? skipped : applicable,
  }));
  const files = (node) => byNode[node].map((path) => ({ path: pathFor(path), content: examples[profile][path] }));
  const proposal = snapshot('proposal', files('proposal'));
  skipped.dependencies = [{ artifactId: 'ART-proposal', revision: proposal.revision }];
  const specs = snapshot('specs', files('specs'), [['proposal', proposal.revision]]);
  const design = skipDesign ? null : snapshot('design', files('design'), [['proposal', proposal.revision]]);
  const designRevision = design?.revision ?? notApplicableArtifactRevision({
    node: 'design', artifactId: 'ART-design', reason: skipped.reason, sourceRevision, workflowRevision: expectedWorkflow,
    dependencies: skipped.dependencies,
  });
  const tasks = snapshot('tasks', files('tasks'), [['specs', specs.revision], ['design', designRevision]]);
  return {
    changeId: profile === 'standard' ? 'CHG-remember-filter' : 'CHG-count-summary',
    workflowSource, expectedWorkflow, sourceRevision, bindings,
    snapshots: [proposal, specs, ...(design === null ? [] : [design]), tasks],
  };
}

function replaceSnapshot(input, node, patch) {
  const prior = input.snapshots.find((entry) => entry.node === node);
  assert.ok(prior);
  const updated = captureArtifactSnapshot({
    contractVersion: 1, id: prior.id, node,
    files: prior.files.map(({ path, content }) => ({ path, content })),
    dependencies: prior.dependencies,
    ...patch,
  });
  return { ...input, snapshots: input.snapshots.map((entry) => entry.node === node ? updated : entry) };
}

const states = (report) => Object.fromEntries(report.assessments.map((entry) => [entry.node, entry.readiness]));

test('original Standard and Compact examples parse as coherent supplied document sets', () => {
  for (const profile of ['standard', 'compact']) {
    const result = parseMarkdownSet(sources(profile));
    assert.equal(result.state, 'valid', JSON.stringify(result));
    assert.equal(result.documents.length, exampleFiles[profile].length);
    assert.ok(Object.isFrozen(result.documents));
    const tasks = result.documents.find((document) => document.kind === 'tasks');
    assert.ok(tasks.declarations.some((entry) => entry.kind === 'task'));
    assert.ok(tasks.declarations.some((entry) => entry.kind === 'check'));
    assert.equal(Object.hasOwn(tasks, 'approved'), false);
    assert.equal(Object.hasOwn(tasks, 'evidence'), false);
  }
});

test('the parser preserves full prose, original source and precise definition locations', () => {
  const source = examples.standard['specs/filters.md'];
  const result = parseExample('specs/filters.md');
  assert.equal(result.state, 'parsed');
  const document = result.document;
  assert.equal(document.source, source);
  assert.equal(document.rawRevision, digestContent(source));
  assert.equal(document.rawRevision, document.intentRevision);
  const requirement = document.declarations[0];
  assert.match(requirement.prose, /without changing access/u);
  assert.equal(requirement.location.offset, source.indexOf('### REQ-filter:'));
  assert.equal(requirement.location.line, source.slice(0, requirement.location.offset).split('\n').length);
  assert.equal(requirement.location.column, 1);
  assert.ok(Object.isFrozen(document));
  assert.ok(Object.isFrozen(document.sections[0]));
  assert.ok(Object.isFrozen(requirement));
});

test('only recognized task-heading completion markers are excluded from intent identity', () => {
  const original = examples.standard['tasks.md'];
  const unchecked = parseExample('tasks.md').document;
  for (const marker of ['x', 'X']) {
    const checked = parseExample('tasks.md', original.replace('### [ ] TSK-filter', `### [${marker}] TSK-filter`)).document;
    assert.notEqual(checked.rawRevision, unchecked.rawRevision);
    assert.equal(checked.intentRevision, unchecked.intentRevision);
    assert.equal(checked.declarations[0].intentRevision, unchecked.declarations[0].intentRevision);
    assert.equal(checked.declarations[0].progressClaim, 'checked');
    assert.equal(Object.hasOwn(checked.declarations[0], 'completed'), false);
  }
  const proseA = parseExample('tasks.md', `${original}\n- [ ] A reviewer note.\n`).document;
  const proseB = parseExample('tasks.md', `${original}\n- [x] A reviewer note.\n`).document;
  assert.notEqual(proseA.intentRevision, proseB.intentRevision);
  const changed = parseExample('tasks.md', original.replace('permission checks unchanged', 'permission checks and ordering unchanged')).document;
  assert.notEqual(changed.intentRevision, unchecked.intentRevision);
});

test('progress-looking text inside a normal code fence is prose, not a task declaration', () => {
  const text = `${examples.standard['proposal.md']}\n\n\`\`\`markdown\n### [ ] TSK-fake: Example only\n\`\`\`\n`;
  const result = parseExample('proposal.md', text);
  assert.equal(result.state, 'parsed');
  assert.equal(result.document.declarations.length, 0);
  const edited = parseExample('proposal.md', text.replace('[ ] TSK-fake', '[x] TSK-fake'));
  assert.notEqual(result.document.intentRevision, edited.document.intentRevision);
});

test('CRLF documents retain raw bytes and still normalize only task progress claims', () => {
  const raw = examples.standard['tasks.md'].replaceAll('\n', '\r\n');
  const parsed = parseExample('tasks.md', raw);
  const checked = parseExample('tasks.md', raw.replace('### [ ] TSK-filter', '### [x] TSK-filter'));
  assert.equal(parsed.state, 'parsed');
  assert.equal(checked.state, 'parsed');
  assert.equal(parsed.document.intentRevision, checked.document.intentRevision);
  assert.equal(parsed.document.rawRevision, digestContent(raw));
  assert.notEqual(parsed.document.rawRevision, parseExample('tasks.md').document.rawRevision);
});

test('frontmatter rejects absent, malformed, unknown-version and unknown-field metadata', () => {
  const original = examples.standard['proposal.md'];
  const invalid = [
    original.replace(/^---\n/u, ''),
    original.replace('schemaVersion: 1', 'schemaVersion: 2'),
    original.replace('schemaVersion: 1', 'schemaVersion: "1"'),
    original.replace('schemaVersion: 1', 'schemaVersion: 1\nschemaVersion: 1'),
    original.replace('schemaVersion: 1', 'schemaVersion: ['),
    original.replace('kind: proposal', 'kind: unknown'),
    original.replace('id: ART-filter-proposal', 'id: REQ-wrong-kind'),
    original.replace('changeId: CHG-remember-filter', 'changeId: ../unsafe'),
    original.replace('kind: proposal', 'kind: proposal\napproved: true'),
    original.replace('kind: proposal', 'kind: !!str proposal'),
    original.replace('id: ART-filter-proposal', 'id: &identity ART-filter-proposal'),
    original.replace('id: ART-filter-proposal', 'id: *identity'),
  ];
  for (const content of invalid) assert.equal(parseExample('proposal.md', content).state, 'invalid', content);
});

test('unsafe paths and rejected YAML values do not leak into diagnostic messages', () => {
  const secret = 'rejected-secret-value';
  const badPath = parseMarkdownDocument({ path: `../${secret}.md`, content: examples.standard['proposal.md'] });
  assert.equal(badPath.state, 'invalid');
  assert.equal(badPath.diagnostics[0].location.path, null);
  assert.equal(JSON.stringify(badPath).includes(secret), false);
  const unknown = parseExample('proposal.md', examples.standard['proposal.md'].replace('kind: proposal', `kind: proposal\n${secret}: ${secret}`));
  assert.equal(unknown.state, 'invalid');
  assert.equal(JSON.stringify(unknown.diagnostics).includes(secret), false);
  const badDeclaration = parseExample('tasks.md', examples.standard['tasks.md'].replace('dependsOn: []', `dependsOn: [${secret}]`));
  assert.equal(badDeclaration.state, 'invalid');
  assert.equal(JSON.stringify(badDeclaration.diagnostics).includes(secret), false);
  assert.ok(badDeclaration.diagnostics[0].location.line > 1);
});

test('required sections and one document title are enforced without treating headings as IDs', () => {
  const source = examples.standard['proposal.md'];
  const cases = [
    [source.replace('## Scope', '## Problem'), 'duplicate-section'],
    [source.replace('## Scope', '## Unknown'), 'invalid-section'],
    [source.replace(/## Acceptance[\s\S]*$/u, ''), 'missing-section'],
    [source.replace(/## Scope[\s\S]*?(?=## Acceptance)/u, '## Scope\n\n'), 'empty-section'],
    [`${source}\n# Another title\n`, 'invalid-title'],
    [source.replace('# Remember the selected filter', 'Remember the selected filter\n============================'), 'invalid-section'],
  ];
  for (const [content, code] of cases) {
    const result = parseExample('proposal.md', content);
    assert.equal(result.state, 'invalid');
    assert.ok(codes(result).includes(code), JSON.stringify(result));
  }
});

test('typed declarations reject missing metadata, missing prose, illegal placement and extra fields', () => {
  const original = examples.standard['tasks.md'];
  const invalid = [
    original.replace('### [ ] TSK-filter', '### TSK-filter'),
    original.replace('### [ ] TSK-filter', '### [yes] TSK-filter'),
    original.replace('### [ ] TSK-filter', '###  [x] TSK-filter'),
    original.replace('### [ ] TSK-filter', '#### [ ] TSK-filter'),
    original.replace('```missionspec', '```yaml'),
    original.replace('```missionspec', '```missionspec executable'),
    original.replace('dependsOn: []', 'dependsOn: []\ncompleted: true'),
    original.replace('dependsOn: []', 'dependsOn: [TSK-filter]'),
    original.replace('checks: [CHK-filter]', 'checks: [REQ-filter]'),
    original.replace('writeScope: [src/filter-preference.ts, tests/filter-preference.test.ts]', 'writeScope: [../outside]'),
    original.replace('writeScope: [src/filter-preference.ts, tests/filter-preference.test.ts]', 'writeScope: [src/**]'),
    original.replace('requirements: [REQ-filter]', 'requirements: [REQ-filter, REQ-filter]'),
    original.replace(/Implement validated restoration[\s\S]*?(?=### \[ \] TSK-reset)/u, ''),
  ];
  for (const content of invalid) assert.equal(parseExample('tasks.md', content).state, 'invalid', content);
  const unexpected = parseExample('proposal.md', `${examples.standard['proposal.md']}\n\`\`\`missionspec\napproved: true\n\`\`\`\n`);
  assert.ok(codes(unexpected).includes('unexpected-metadata'));
});

test('duplicate document/fact identities and canonical check definitions are rejected across files', () => {
  const original = sources();
  const copy = { ...original[1], path: 'other-spec.md' };
  const duplicate = parseMarkdownSet([...original, copy]);
  assert.equal(duplicate.state, 'invalid');
  assert.ok(codes(duplicate).includes('duplicate-identity'));
  const verification = examples.standard['tasks.md']
    .replace('id: ART-filter-tasks', 'id: ART-verification')
    .replace('kind: tasks', 'kind: verification')
    .replace(/## Tasks[\s\S]*?(?=## Checks)/u, '');
  const duplicateCheck = parseMarkdownSet([...original, { path: 'verification.md', content: verification }]);
  assert.equal(duplicateCheck.state, 'invalid');
  assert.ok(codes(duplicateCheck).includes('duplicate-identity'));
});

test('references resolve by stable type and identity across the full declared source set', () => {
  const full = sources();
  const missing = parseMarkdownSet(full.filter((source) => !source.path.endsWith('specs/reset.md')));
  assert.equal(missing.state, 'invalid');
  assert.ok(codes(missing).includes('invalid-reference'));
  const mixed = parseMarkdownSet(full.map((source, index) => index === 1 ? {
    ...source, content: source.content.replace('CHG-remember-filter', 'CHG-other'),
  } : source));
  assert.ok(codes(mixed).includes('mixed-changes'));
  const renamed = full.map((source) => ({
    ...source, content: source.content.replace('REQ-filter: Restore a saved filter', 'REQ-filter: A clearer title'),
  }));
  assert.equal(parseMarkdownSet(renamed).state, 'valid');
});

test('explicit removals retain a reason but active declarations cannot reference removed facts', () => {
  const removed = examples.standard['specs/filters.md'].replaceAll('operation: add', 'operation: remove');
  assert.equal(parseMarkdownSet([{ path: 'filters.md', content: removed }]).state, 'valid');
  const activeScenario = removed.replace('operation: remove\nrequirement:', 'operation: add\nrequirement:');
  const invalid = parseMarkdownSet([{ path: 'filters.md', content: activeScenario }]);
  assert.ok(codes(invalid).includes('removed-reference'));
  const staleTask = parseMarkdownSet(sources().map((source) => source.path.endsWith('specs/filters.md') ? { ...source, content: removed } : source));
  assert.ok(codes(staleTask).includes('removed-reference'));
});

test('task graph references reject missing dependencies and cycles, not just self-links', () => {
  for (const [dependency, code] of [['TSK-missing', 'invalid-reference'], ['TSK-reset', 'task-cycle']]) {
    const input = sources().map((source) => source.path.endsWith('tasks.md') ? {
      ...source, content: source.content.replace('dependsOn: []', `dependsOn: [${dependency}]`),
    } : source);
    const result = parseMarkdownSet(input);
    assert.equal(result.state, 'invalid');
    assert.ok(codes(result).includes(code));
  }
  const combined = sources().map((source) => source.path.endsWith('tasks.md') ? {
    ...source,
    content: source.content.replace('dependsOn: []', 'dependsOn: [TSK-reset]')
      .replace('checks: [CHK-filter]', 'checks: [CHK-undefined]'),
  } : source);
  const result = parseMarkdownSet(combined);
  assert.ok(codes(result).includes('invalid-reference'));
  assert.ok(codes(result).includes('task-cycle'));
});

test('project principles are explicitly project-wide, not fake change approvals', () => {
  const document = `---\nschemaVersion: 1\nid: ART-principles\nkind: principles\n---\n# Project principles\n\n## Principles\n\nPreserve user edits and disclose unavailable evidence.\n`;
  assert.equal(parseMarkdownDocument({ path: 'missionspec/principles.md', content: document }).document.changeId, null);
  const bad = document.replace('kind: principles', 'kind: principles\nchangeId: CHG-other');
  assert.equal(parseMarkdownDocument({ path: 'missionspec/principles.md', content: bad }).state, 'invalid');
});

test('Standard is default and Compact is explicit without weakened authority or DAG semantics', () => {
  assert.equal(parseWorkflowProfile(), 'standard');
  assert.equal(parseWorkflowProfile('compact'), 'compact');
  assert.throws(() => parseWorkflowProfile('fast'), ContractError);
  for (const [profile, source] of [['standard', standardWorkflow], ['compact', compactWorkflow]]) {
    const workflow = parseArtifactWorkflow(source);
    assert.equal(workflow.profile, profile);
    assert.equal(workflow.revision, digestContent(source));
    assert.deepEqual(workflow.order, ['proposal', 'specs', 'design', 'tasks']);
    assert.deepEqual(workflow.nodes.find((node) => node.id === 'tasks').dependsOn, ['specs', 'design']);
    assert.equal(workflow.nodes.find((node) => node.id === 'specs').outputMode, 'declared-set');
    assert.deepEqual(workflow.nodes.find((node) => node.id === 'tasks').additionalSections, profile === 'compact' ? ['Design'] : []);
    assert.ok(Object.isFrozen(workflow.nodes[0].dependsOn));
  }
});

function workflowData(source = standardWorkflow) {
  const workflow = parseArtifactWorkflow(source);
  return { schemaVersion: 1, profile: workflow.profile, nodes: workflow.nodes.map((node) => ({ ...node })), targets: workflow.targets };
}

test('workflow parsing rejects cycles, missing dependencies and weakened or unknown declarations', () => {
  const mutations = [
    (data) => { data.schemaVersion = 2; },
    (data) => { data.profile = 'automatic'; },
    (data) => { data.approved = true; },
    (data) => { data.nodes[0].dependsOn = ['tasks']; },
    (data) => { data.nodes[1].dependsOn = ['missing']; },
    (data) => { data.nodes[3].dependsOn = ['specs']; },
    (data) => { data.nodes[3].skip = 'explicit'; },
    (data) => { data.nodes[1].outputMode = 'single'; },
    (data) => { data.nodes.push({ ...data.nodes[0] }); },
    (data) => { data.targets = ['unknown']; },
  ];
  for (const mutate of mutations) {
    const data = workflowData();
    mutate(data);
    assert.throws(() => parseArtifactWorkflow(stringify(data)), ContractError, mutate.toString());
  }
  assert.throws(() => parseArtifactWorkflow(`${standardWorkflow}\nprofile: compact\n`), ContractError);
  assert.throws(() => parseArtifactWorkflow(standardWorkflow.replace('profile: standard', 'profile: &profile standard')), ContractError);
});

test('dependency closure is topological, complete and bounded by explicit targets', () => {
  assert.deepEqual(artifactDependencyClosure(standardWorkflow), ['proposal', 'specs', 'design', 'tasks']);
  assert.deepEqual(artifactDependencyClosure(standardWorkflow, ['specs']), ['proposal', 'specs']);
  assert.deepEqual(artifactDependencyClosure(standardWorkflow, ['design', 'specs']), ['proposal', 'specs', 'design']);
  assert.throws(() => artifactDependencyClosure(standardWorkflow, ['unknown']), ContractError);
  assert.throws(() => artifactDependencyClosure(standardWorkflow, ['specs', 'specs']), ContractError);
});

test('valid supplied Standard snapshots produce structural readiness, not implementation approval', () => {
  const report = assessArtifactReadiness(fixture());
  assert.deepEqual(states(report), { proposal: 'valid', specs: 'valid', design: 'valid', tasks: 'valid' });
  assert.deepEqual(report.next, { state: 'all-current' });
  assert.deepEqual(report.requiredClosure, ['proposal', 'specs', 'design', 'tasks']);
  assert.deepEqual(report.remainingClosure, []);
  assert.deepEqual(report.diagnostics, []);
  assert.equal(Object.hasOwn(report, 'approved'), false);
  assert.equal(Object.hasOwn(report, 'implemented'), false);
  assert.ok(Object.isFrozen(report.assessments[0]));
});

test('missing inputs never become ready because a filename or completion flag was supplied', () => {
  const input = fixture();
  const report = assessArtifactReadiness({ ...input, snapshots: [] });
  assert.deepEqual(states(report), { proposal: 'missing', specs: 'blocked', design: 'blocked', tasks: 'blocked' });
  assert.deepEqual(report.next, { state: 'ready', node: 'proposal' });
  const invalid = replaceSnapshot(input, 'proposal', {
    files: [{ path: pathFor('proposal.md'), content: '# A filename is not a valid artifact.\n' }],
  });
  assert.equal(states(assessArtifactReadiness(invalid)).proposal, 'blocked');
  assert.throws(() => assessArtifactReadiness({ ...input, approved: true }), ContractError);
});

test('parallel ready branches require selection; selectors cannot bypass prerequisites', () => {
  const input = fixture();
  const partial = { ...input, snapshots: input.snapshots.filter((entry) => entry.node === 'proposal') };
  assert.deepEqual(assessArtifactReadiness(partial).next, { state: 'selection-required', candidates: ['specs', 'design'] });
  assert.deepEqual(assessArtifactReadiness({ ...partial, selected: 'specs' }).next, { state: 'ready', node: 'specs' });
  const blocked = assessArtifactReadiness({ ...partial, selected: 'tasks' });
  assert.equal(blocked.next.state, 'blocked');
  assert.ok(blocked.diagnostics.some((entry) => entry.code === 'selection-not-actionable'));
  assert.throws(() => assessArtifactReadiness({ ...partial, selected: '../tasks' }), ContractError);
  assert.throws(() => assessArtifactReadiness({ ...partial, selected: 'unknown' }), ContractError);
});

test('the specs artifact requires the whole exact declared multi-file set', () => {
  const input = fixture();
  const specs = input.snapshots.find((entry) => entry.node === 'specs');
  for (const files of [
    specs.files.slice(0, 1),
    [...specs.files, { path: pathFor('specs/extra.md'), content: examples.standard['specs/filters.md'] }],
  ]) {
    const result = assessArtifactReadiness(replaceSnapshot(input, 'specs', {
      files: files.map(({ path, content }) => ({ path, content })),
    }));
    assert.equal(states(result).specs, 'blocked');
    assert.ok(result.diagnostics.some((entry) => entry.code === 'output-set-mismatch'));
    assert.notEqual(result.next.state, 'all-current');
  }
  const globs = structuredClone(input);
  globs.bindings[1].declaredOutputs = ['missionspec/changes/example/specs/**'];
  assert.throws(() => assessArtifactReadiness(globs), ContractError);
});

test('supplied snapshot digests and versions are independently recomputed, never trusted as flags', () => {
  const input = fixture();
  for (const change of [
    (entry) => { entry.contractVersion = 9; },
    (entry) => { entry.files[0].content += '\nManual edit\n'; },
    (entry) => { entry.files[0].digest = digestContent('fake'); },
    (entry) => { entry.revision = digestContent('fake'); },
  ]) {
    const altered = structuredClone(input);
    change(altered.snapshots[0]);
    const report = assessArtifactReadiness(altered);
    assert.equal(states(report).proposal, 'blocked');
    assert.ok(report.diagnostics.some((entry) => entry.code === 'invalid-snapshot'));
  }
});

test('edited upstream content makes frozen descendants stale and preserves review selection', () => {
  const input = fixture();
  const proposal = input.snapshots[0];
  const changed = replaceSnapshot(input, 'proposal', {
    files: proposal.files.map(({ path, content }) => ({ path, content: content.replace('visible reset action', 'clearly labeled reset action') })),
  });
  const report = assessArtifactReadiness(changed);
  assert.deepEqual(states(report), { proposal: 'valid', specs: 'stale', design: 'stale', tasks: 'stale' });
  assert.deepEqual(report.next, { state: 'selection-required', candidates: ['specs', 'design'] });
  assert.ok(report.diagnostics.some((entry) => entry.code === 'dependency-revision-mismatch'));
  assert.ok(report.diagnostics.some((entry) => entry.node === 'tasks' && entry.code === 'dependency-not-current'));
});

test('missing/extra declared dependency records block rather than assert historic freshness', () => {
  const input = fixture();
  const report = assessArtifactReadiness(replaceSnapshot(input, 'tasks', { dependencies: [] }));
  assert.equal(states(report).tasks, 'blocked');
  assert.ok(report.diagnostics.some((entry) => entry.code === 'dependency-set-mismatch'));
});

test('Compact combines design prose but requires an explicit revision-bound design skip', () => {
  const input = fixture('compact');
  const report = assessArtifactReadiness(input);
  assert.deepEqual(states(report), { proposal: 'valid', specs: 'valid', design: 'not-applicable', tasks: 'valid' });
  assert.deepEqual(report.requiredClosure, ['proposal', 'specs', 'tasks']);
  assert.deepEqual(report.next, { state: 'all-current' });
  const required = structuredClone(input);
  required.bindings[2].applicability = { state: 'required' };
  assert.equal(states(assessArtifactReadiness(required)).design, 'missing');
  assert.deepEqual(assessArtifactReadiness(required).next, { state: 'ready', node: 'design' });
  for (const invalid of [
    { ...input.bindings[2].applicability, reason: '' },
    { state: 'not-applicable', reason: 'Short change' },
    { ...input.bindings[2].applicability, approved: true },
  ]) {
    const changed = structuredClone(input);
    changed.bindings[2].applicability = invalid;
    assert.throws(() => assessArtifactReadiness(changed), ContractError);
  }
});

test('skip decisions go stale with source changes and cannot coexist with a hidden artifact', () => {
  const compact = fixture('compact');
  const stale = assessArtifactReadiness({ ...compact, sourceRevision: digestContent('edited source') });
  assert.equal(states(stale).design, 'stale');
  assert.equal(stale.next.state, 'blocked');
  assert.ok(stale.diagnostics.some((entry) => entry.code === 'skip-stale'));
  const standard = fixture();
  const skip = structuredClone(standard);
  skip.bindings[2].applicability = {
    state: 'not-applicable', reason: 'Small change', sourceRevision,
    dependencies: [{ artifactId: 'ART-proposal', revision: standard.snapshots[0].revision }],
  };
  const conflicting = assessArtifactReadiness(skip);
  assert.equal(states(conflicting).design, 'blocked');
  assert.ok(conflicting.diagnostics.some((entry) => entry.code === 'skip-has-content'));
  const changedProposal = replaceSnapshot(compact, 'proposal', {
    files: compact.snapshots[0].files.map(({ path, content }) => ({ path, content: `${content}\nA new material constraint.\n` })),
  });
  const changed = assessArtifactReadiness(changedProposal);
  assert.equal(states(changed).design, 'stale');
  assert.ok(changed.diagnostics.some((entry) => entry.node === 'design' && entry.code === 'dependency-revision-mismatch'));
});

test('Compact does not silently omit its combined Design section or relax typed references', () => {
  const input = fixture('compact');
  const tasks = input.snapshots.find((entry) => entry.node === 'tasks');
  const report = assessArtifactReadiness(replaceSnapshot(input, 'tasks', {
    files: tasks.files.map(({ path, content }) => ({ path, content: content.replace(/## Design[\s\S]*?(?=## Tasks)/u, '') })),
  }));
  assert.equal(states(report).tasks, 'blocked');
  assert.ok(report.diagnostics.some((entry) => entry.code === 'additional-section-missing'));
});

test('changing task progress does not invent evidence and leaves structurally valid documents valid', () => {
  const input = fixture();
  const tasks = input.snapshots.find((entry) => entry.node === 'tasks');
  const checked = replaceSnapshot(input, 'tasks', {
    files: tasks.files.map(({ path, content }) => ({ path, content: content.replaceAll('### [ ] TSK-', '### [x] TSK-') })),
  });
  const before = assessArtifactReadiness(input);
  const after = assessArtifactReadiness(checked);
  assert.deepEqual(states(after), states(before));
  assert.notEqual(after.assessments[3].revision, before.assessments[3].revision);
  assert.equal(Object.hasOwn(after, 'accepted'), false);
});

test('workflow pin, complete binding inventory and output ownership are enforced', () => {
  const input = fixture();
  for (const mutate of [
    (value) => { value.expectedWorkflow = digestContent('a different workflow'); },
    (value) => { value.bindings.pop(); },
    (value) => { value.bindings[1].node = 'proposal'; },
    (value) => { value.bindings[1].artifactId = 'ART-proposal'; },
    (value) => { value.bindings[1].declaredOutputs = [pathFor('proposal.md')]; },
    (value) => { value.bindings[3].applicability = { state: 'not-applicable', reason: 'No tasks', sourceRevision }; },
    (value) => { value.snapshots.push(value.snapshots[0]); },
    (value) => { value.snapshots[0].node = 'undeclared'; },
  ]) {
    const invalid = structuredClone(input);
    mutate(invalid);
    assert.throws(() => assessArtifactReadiness(invalid), ContractError, mutate.toString());
  }
});

test('a coherent document set from another change cannot satisfy the selected change', () => {
  const report = assessArtifactReadiness({ ...fixture(), changeId: 'CHG-different' });
  assert.equal(report.next.state, 'blocked');
  assert.ok(report.assessments.every((entry) => entry.readiness === 'blocked'));
  assert.ok(report.diagnostics.some((entry) => entry.code === 'document-change-mismatch'));
});
