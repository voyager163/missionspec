import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { parseDocument } from 'yaml';

const assetRoot = new URL('../assets/operations/', import.meta.url);
const yaml = parseDocument(await readFile(new URL('manifest.yaml', assetRoot), 'utf8'));
assert.deepEqual(yaml.errors, [], 'manifest must parse without YAML errors');
assert.deepEqual(yaml.warnings, [], 'manifest must parse without YAML warnings');
const manifest = yaml.toJS();
const schema = JSON.parse(await readFile(new URL('../assets/schemas/operation-manifest.schema.json', import.meta.url), 'utf8'));
const primary = ['discover', 'draft', 'draft-all', 'implement', 'verify', 'archive'];
const supporting = ['revise', 'clarify', 'analyze', 'principles', 'sync', 'onboard'];
const ids = [...primary, ...supporting];
const bodies = Object.fromEntries(await Promise.all(ids.map(async (id) =>
  [id, await readFile(new URL(`${id}.md`, assetRoot), 'utf8')],
)));
const words = (text) => text === '' ? [] : text.split(' ');
const sorted = (values) => [...values].sort();

const ajv = new Ajv2020({ strict: true, allErrors: true });
const validators = new Map();

function validate(value, node = schema) {
  if (!validators.has(node)) {
    validators.set(node, ajv.compile(node));
  }
  const validator = validators.get(node);
  assert(validator(value), ajv.errorsText(validator.errors, { separator: '\n' }));
}

const expected = {
  discover: {
    description: 'Explore a problem, compare options, and surface uncertainties through read-only investigation; save findings only with explicit change-local capture scope.',
    owner: 'discovery', required: 'workspace request', optional: 'change context-observations capture-scope',
    outputs: 'findings questions discovery-notes', effects: 'change-create discovery-write',
    prerequisites: 'workspace-boundary authoritative-instructions capture-runtime',
    approvals: 'capture-scope explicit-change-creation host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect material-question capture-complete',
    handoffs: 'clarify draft draft-all', telemetry: 'none',
  },
  draft: {
    description: 'Draft one next ready artifact for a selected change, including a declared multi-file specs set; validate it and stop before implementation.',
    owner: 'specification', required: 'workspace change workflow-state', optional: 'artifact-selector change-creation-scope',
    outputs: 'artifact-patch validation-findings readiness-report', effects: 'change-create artifact-write',
    prerequisites: 'workspace-boundary authoritative-instructions operation-runtime pinned-workflow current-dependencies',
    approvals: 'artifact-scope explicit-change-creation host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect material-question invalid-dependencies one-artifact-complete drafts-current before-implementation',
    handoffs: 'draft draft-all clarify revise analyze implement', telemetry: 'stateful-top-level',
  },
  'draft-all': {
    description: 'Prepare the remaining required drafts for a new or existing change using its pinned workflow; pause at blockers and stop before implementation.',
    owner: 'specification', required: 'workspace change workflow-state', optional: 'change-creation-scope',
    outputs: 'artifact-patch validation-findings readiness-report', effects: 'change-create artifact-write',
    prerequisites: 'workspace-boundary authoritative-instructions operation-runtime pinned-workflow current-dependencies',
    approvals: 'artifact-closure-scope explicit-change-creation host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect material-question invalid-dependencies review-gate prerequisite-closure-complete before-implementation',
    handoffs: 'draft clarify revise analyze implement', telemetry: 'stateful-top-level',
  },
  implement: {
    description: 'Implement explicitly authorized tasks with current revision-bound authority; Interactive is default and Auto requires a bounded grant and confirmed run limits.',
    owner: 'execution', required: 'workspace change approved-revisions execution-grant task-graph', optional: 'auto-request run-reference',
    outputs: 'attempt-records progress-report blocker-report', effects: 'source-write project-check-execute dependency-change host-dispatch execution-record',
    prerequisites: 'workspace-boundary authoritative-instructions operation-runtime current-dependencies current-execution-grant qualified-host durable-ledger',
    approvals: 'separate-implementation-request revision-bound-grant explicit-auto per-run-limits material-change-reapproval host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect material-question stale-revision revoked-authority run-limit two-repairs no-progress unknown-outcome ledger-failure task-scope-complete',
    handoffs: 'verify revise clarify', telemetry: 'stateful-top-level',
  },
  verify: {
    description: 'Compare saved implementation against approved intent using authorized checks and source-bound evidence; report gaps without standalone repairs or acceptance.',
    owner: 'verification', required: 'workspace change approved-revisions source-revision check-plan', optional: 'verification-grant evidence',
    outputs: 'check-observations gap-report proposed-repairs', effects: 'project-check-execute evidence-record',
    prerequisites: 'workspace-boundary authoritative-instructions operation-runtime current-dependencies source-binding durable-ledger',
    approvals: 'verification-check-scope evidence-scope host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect stale-revision unavailable-check ledger-failure report-complete no-standalone-repair',
    handoffs: 'implement revise analyze archive', telemetry: 'stateful-top-level',
  },
  archive: {
    description: 'Guide explicit acceptance, eligible spec promotion, and change closure; preserve the actual outcome without treating cancelled or incomplete work as success.',
    owner: 'specification', required: 'workspace change outcome-selection', optional: 'evidence acceptance-record sync-preview',
    outputs: 'acceptance-record sync-result closure-record', effects: 'acceptance-record baseline-write closure-write',
    prerequisites: 'workspace-boundary authoritative-instructions operation-runtime current-dependencies durable-ledger shared-sync-engine',
    approvals: 'explicit-acceptance exact-sync-preview explicit-outcome-closure host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect stale-revision acceptance-ineligible sync-conflict partial-effect archive-collision ledger-failure closure-complete',
    handoffs: 'verify sync revise', telemetry: 'stateful-top-level',
  },
  revise: {
    description: 'Amend existing change documents through a reviewed scoped patch; report downstream staleness and invalidated authority without implementing code.',
    owner: 'specification', required: 'workspace change existing-artifacts amendment-scope', optional: 'gap-report',
    outputs: 'artifact-patch impact-report validation-findings', effects: 'artifact-write revision-invalidation',
    prerequisites: 'workspace-boundary authoritative-instructions operation-runtime current-dependencies',
    approvals: 'reviewed-revision-patch material-change-reapproval host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect material-question new-artifact-needed stale-revision patch-complete before-implementation',
    handoffs: 'draft clarify analyze implement verify', telemetry: 'stateful-top-level',
  },
  clarify: {
    description: 'Resolve consequential ambiguities in an existing change and capture only authorized answers; clarification never grants implementation approval.',
    owner: 'discovery', required: 'workspace change existing-artifacts ambiguity-scope', optional: 'answers capture-scope',
    outputs: 'questions answer-patch unresolved-questions impact-report', effects: 'artifact-write revision-invalidation',
    prerequisites: 'workspace-boundary authoritative-instructions capture-runtime current-dependencies',
    approvals: 'answer-capture-scope host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect question-bound unanswered-question stale-revision capture-complete',
    handoffs: 'revise draft analyze', telemetry: 'none',
  },
  analyze: {
    description: 'Review artifact consistency, coverage, and requirements quality without executing project code; report findings without fixes or automatic checklist approval.',
    owner: 'planning', required: 'workspace change existing-artifacts', optional: 'project-principles capture-scope',
    outputs: 'validation-findings coverage-report quality-findings', effects: 'analysis-report-write',
    prerequisites: 'workspace-boundary authoritative-instructions capture-runtime current-dependencies',
    approvals: 'report-capture-scope host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect report-complete no-project-execution',
    handoffs: 'clarify revise draft', telemetry: 'none',
  },
  principles: {
    description: 'Create or amend optional project-wide MissionSpec principles with explicit document scope and impact review; principles grant no runtime permissions.',
    owner: 'specification', required: 'workspace principle-scope', optional: 'project-principles active-changes',
    outputs: 'principles-patch impact-report', effects: 'principles-write revision-invalidation',
    prerequisites: 'workspace-boundary authoritative-instructions operation-runtime current-dependencies',
    approvals: 'project-principles-scope reviewed-revision-patch host-permissions',
    stops: 'missing-runtime-for-effects unauthorized-effect material-question stale-revision patch-complete no-runtime-grants',
    handoffs: 'analyze revise discover', telemetry: 'stateful-top-level',
  },
  sync: {
    description: 'Promote eligible accepted deltas through the shared freshness, confirmation, and conflict checks; update baseline specs while leaving the change open.',
    owner: 'specification', required: 'workspace change baseline-revisions accepted-deltas acceptance-record', optional: 'evidence sync-preview',
    outputs: 'sync-preview sync-result', effects: 'baseline-write',
    prerequisites: 'workspace-boundary authoritative-instructions operation-runtime current-dependencies durable-ledger shared-sync-engine',
    approvals: 'current-acceptance exact-sync-preview host-permissions',
    stops: 'missing-runtime-for-effects ambiguous-selection unauthorized-effect stale-revision acceptance-ineligible sync-conflict partial-effect ledger-failure sync-complete-leave-open',
    handoffs: 'verify revise archive', telemetry: 'stateful-top-level',
  },
  onboard: {
    description: 'Explain MissionSpec and guide a selected walkthrough from current readiness; keep every state-changing action separately authorized and never auto-initialize.',
    owner: 'integration', required: 'workspace host-readiness', optional: 'walkthrough-selection',
    outputs: 'readiness-report guidance', effects: '',
    prerequisites: 'workspace-boundary authoritative-instructions',
    approvals: 'each-action-separately host-permissions',
    stops: 'missing-runtime-for-effects unauthorized-effect explanation-complete selected-step-boundary',
    handoffs: 'discover draft draft-all implement verify archive revise clarify analyze principles sync', telemetry: 'none',
  },
};

test('source catalog has exactly twelve default operations and all three target hosts', async () => {
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.defaultInstall, true);
  assert.deepEqual(sorted(manifest.hosts), ['claude', 'codex', 'copilot']);
  assert.deepEqual(manifest.rendering, { invocationPlaceholder: '{{invocation}}' });
  assert.deepEqual(sorted(Object.keys(manifest.operations)), sorted(ids));
  assert.deepEqual(sorted(await readdir(assetRoot)), sorted(['manifest.yaml', ...ids.map((id) => `${id}.md`)]));
  assert.equal(new Set(Object.values(bodies)).size, ids.length, 'each operation needs its own original body');
});

test('source metadata compiles and validates with strict Ajv2020 and a closed schema', () => {
  validate(manifest);
  assert.deepEqual(sorted(schema.properties.operations.required), sorted(ids));
  assert.deepEqual(sorted(Object.keys(schema.properties.operations.properties)), sorted(ids));
  assert.deepEqual(sorted(schema.$defs.operationId.enum), sorted(ids));
});

test('schema vocabularies exactly cover the declared contract inputs, outputs and boundaries', () => {
  const operations = Object.values(manifest.operations);
  const used = {
    input: operations.flatMap((operation) => [...operation.inputs.required, ...operation.inputs.optional]),
    output: operations.flatMap((operation) => operation.outputs),
    effect: operations.flatMap((operation) => [...operation.effects.default, ...operation.effects.conditional]),
    prerequisite: operations.flatMap((operation) => operation.prerequisites),
    approvalRule: operations.flatMap((operation) => operation.approvalRules),
    stopRule: operations.flatMap((operation) => operation.stopRules),
  };
  for (const [definition, values] of Object.entries(used)) {
    assert.deepEqual(sorted(schema.$defs[definition].enum), sorted(new Set(values)), definition);
  }
});

test('schema rejects catalog drift, arbitrary permissions, hooks, malformed inputs and dangling handoffs', () => {
  const mutations = [
    (value) => { delete value.operations.verify; },
    (value) => { value.operations.extra = value.operations.discover; },
    (value) => { value.schemaVersion = 2; },
    (value) => { value.defaultInstall = false; },
    (value) => { value.rendering.invocationPlaceholder = '{{shell}}'; },
    (value) => { value.hosts.pop(); },
    (value) => { value.hosts[0] = 'unqualified-custom-host'; },
    (value) => { value.operations.verify.category = 'supporting'; },
    (value) => { value.operations.verify.engineOwner = 'execution'; },
    (value) => { value.operations.draft.body = 'verify.md'; },
    (value) => { value.operations.draft.body = '../../elsewhere.md'; },
    (value) => { delete value.operations.discover.description; },
    (value) => { value.operations.discover.inputs.required = []; },
    (value) => { value.operations.discover.inputs.required.push('arbitrary-prompt'); },
    (value) => { value.operations.discover.outputs.push('anything'); },
    (value) => { value.operations.discover.effects.default = ['source-write']; },
    (value) => { value.operations.implement.effects.conditional.push('shell:*'); },
    (value) => { value.operations.implement.approvalRules.push('allow-all'); },
    (value) => { value.operations.implement.prerequisites.push('trust-agent'); },
    (value) => { value.operations.implement.stopRules = []; },
    (value) => { value.operations.draft.handoffs.push('propose'); },
    (value) => { value.operations.draft.handoffs.push('draft'); },
    (value) => { value.operations.discover.telemetryClass = 'all-invocations'; },
    (value) => { value.operations.draft.hooks = { after: 'arbitrary shell' }; },
    (value) => { value.operations.draft.allowedTools = ['*']; },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(manifest);
    mutate(copy);
    assert.throws(() => validate(copy), undefined, mutate.toString());
  }
});

test('canonical descriptions are required, bounded, nonblank single lines for every operation', () => {
  const descriptionSchema = schema.$defs.operation.properties.description;
  assert.equal(descriptionSchema.minLength, 1);
  assert.equal(descriptionSchema.maxLength, 240);
  assert.equal(new Set(ids.map((id) => manifest.operations[id].description)).size, ids.length);
  for (const id of ids) {
    for (const description of [
      '', '   ', '\t', 'x'.repeat(241), '😀'.repeat(241),
      'first\nsecond', 'trailing\n', '\nleading', 'first\rsecond',
      'trailing\r\n', 'first\u2028second', 'first\u2029second',
    ]) {
      const copy = structuredClone(manifest);
      copy.operations[id].description = description;
      assert.throws(() => validate(copy), undefined, `${id}: reject ${JSON.stringify(description)}`);
    }
  }
  validate('x', descriptionSchema);
  validate('x'.repeat(240), descriptionSchema);
  validate('😀'.repeat(240), descriptionSchema);
});

for (const id of ids) {
  test(`${id}: exact metadata contracts, effect separation, and stable handoffs`, () => {
    const actual = manifest.operations[id];
    const contract = expected[id];
    assert.deepEqual(actual, {
      body: `${id}.md`,
      description: contract.description,
      category: primary.includes(id) ? 'primary' : 'supporting',
      engineOwner: contract.owner,
      inputs: { required: words(contract.required), optional: words(contract.optional) },
      outputs: words(contract.outputs),
      effects: { default: ['workspace-read'], conditional: words(contract.effects) },
      prerequisites: words(contract.prerequisites),
      approvalRules: words(contract.approvals),
      stopRules: words(contract.stops),
      handoffs: words(contract.handoffs),
      telemetryClass: contract.telemetry,
    });
    assert(!actual.inputs.required.some((input) => actual.inputs.optional.includes(input)), 'input cannot be both required and optional');
    const reportSection = bodies[id].split('## Report and handoff')[1]?.split('## Output and privacy')[0];
    const handoffList = reportSection?.match(/handoff IDs[^:]*:\s*([\s\S]*?)\./u)?.[1];
    assert(handoffList, `${id}: missing body handoff list`);
    const bodyHandoffs = [...handoffList.matchAll(/`([^`]+)`/gu)].map((match) => match[1]);
    assert.deepEqual(bodyHandoffs, actual.handoffs, `${id}: body and manifest handoffs differ`);
    for (const handoff of actual.handoffs) {
      assert(Object.hasOwn(manifest.operations, handoff), `dangling handoff: ${handoff}`);
    }
    assert(!actual.effects.conditional.includes('workspace-read'), 'default and conditional effects must not overlap');
  });

  test(`${id}: host-neutral body requires real capabilities, authority, truthful reports and clean protocols`, () => {
    const body = bodies[id];
    const text = body.replace(/\s+/gu, ' ');
    assert.equal((body.match(/\{\{invocation\}\}/gu) ?? []).length, 1);
    assert.deepEqual(body.match(/\{\{[^}]+\}\}/gu), [manifest.rendering.invocationPlaceholder], 'unknown renderer placeholder');
    assert.doesNotMatch(body, /(?:\/|\$)missionspec-|\/opsx:|\bopenspec\b|\bspeckit\b|\bliftoff\b/iu);
    assert.doesNotMatch(body, /missionspec\/changes\/<(?:id|change-id)>/iu);
    assert.doesNotMatch(body, /^\s*(?:hooks|allowed-tools|pre-command|post-command):/gmu);
    for (const contract of [
      /current workspace instructions/iu,
      /authoritative core instructions/iu,
      /engine result contracts/iu,
      /workspace\/worktree/iu,
      /allowed-tools metadata never grant authority/iu,
      /advertised runtime capabilities/iu,
      /missing-runtime/u,
      /## Report and handoff/u,
      /`state`/u,
      /JSON or stdio-MCP mode, stdout contains only the promised result\/protocol messages/iu,
      /human diagnostics belong on stderr/iu,
      /Never send source, specs, prompts, raw errors,/iu,
    ]) {
      assert(contract.test(text), `${id}: ${contract}`);
    }
  });
}

// These assertions protect documented safety contracts from accidental removal.
// They do not prove host enforcement, model compliance, or live qualification.
const sentinels = {
  discover: [
    /default is read-only conversation/iu,
    /only findings destination is\s+`missionspec\/changes\/<change-slug>\/discovery\.md`/u,
    /inside the runtime-returned `changeRoot`/u,
    /Do not construct filesystem paths from a stable ID or choose the newest path/iu,
    /no\s+top-level discovery directory/iu,
    /explicit authorization\s+for its creation/iu,
    /No\s+proposal, design, specs, or tasks are created/iu,
    /does not authorize other authored artifacts/iu,
    /emits no telemetry, including explicit\s+capture/iu,
    /no log files, ledger rows, or telemetry\s+preferences/iu,
  ],
  draft: [
    /exactly one next ready artifact/iu,
    /entire specs set is one artifact/iu,
    /must not also produce design or\s+tasks/iu,
    /artifact selector[\s\S]+cannot bypass dependencies/iu,
    /every draft is\s+current[\s\S]+stop/iu,
    /meaningful outcomes, stable task\s+IDs, typed dependencies/iu,
    /Stop after one artifact/iu,
    /Do not install\s+dependencies, run project tests/iu,
    /ready for implementation review, never approved or implemented/iu,
  ],
  'draft-all': [
    /required artifact dependency\s+closure/iu,
    /same scheduler used by `draft`/iu,
    /Reuse current valid artifacts/iu,
    /Validate each node before advancing/iu,
    /material questions or required\s+human review/iu,
    /optional omissions with a reason and relevant source revision/iu,
    /explicit validated applicability declaration/iu,
    /scoped tasks and appropriate planned checks/iu,
    /Do not install dependencies, run project tests, edit source, or begin\s+implementation/iu,
  ],
  implement: [
    /Interactive is the default/iu,
    /`--auto` requests Auto; it is not an effect grant/u,
    /genuine local-user execution grant/iu,
    /model output[\s\S]+cannot create current authority/iu,
    /Before every Auto run[\s\S]+per-run execution\s+limits/iu,
    /hard, advisory, or unavailable/iu,
    /one task at a time by default/iu,
    /at most two repair attempts per task/iu,
    /initial\s+attempt is not a repair/iu,
    /second unsuccessful repair/iu,
    /no progress[\s\S]+revoked authority[\s\S]+unknown effects/iu,
    /never weaken requirements/iu,
    /quiescence only when confirmed/iu,
  ],
  verify: [
    /actual saved source revision/iu,
    /uncommitted changes/iu,
    /mark affected evidence stale/iu,
    /Tests\s+execute project code and are not intrinsically read-only/iu,
    /failed, unavailable, skipped, missing, stale/iu,
    /completeness, correctness, and coherence separately/iu,
    /missing, partial, contradictory, and unrequested behavior/iu,
    /Standalone verify never repairs code/iu,
    /Do not rewrite tasks or requirements/iu,
    /accept, sync, or archive/iu,
  ],
  archive: [
    /incomplete changes can be archived only with explicit\s+confirmation of that outcome/iu,
    /not accepted successes/iu,
    /must not\s+automatically promote baseline specs/iu,
    /explicit\s+acceptance of the exact presented revision/iu,
    /Acceptance, promotion, and closure remain separately typed records/iu,
    /same\s+sync engine used by `sync`/iu,
    /refuse collisions/iu,
    /recoverable\s+partial state/iu,
    /not confidential raw transcripts/iu,
  ],
  revise: [
    /exact existing artifact\s+set/iu,
    /Several existing artifacts may change/iu,
    /new artifact type or undeclared\s+output[\s\S]+`draft`/iu,
    /Mark affected downstream artifacts stale, invalidate affected grants/iu,
    /reassess evidence applicability/iu,
    /Preserve historical revisions/iu,
    /No code edits, project\s+tests/iu,
  ],
  clarify: [
    /bounded set of consequential questions/iu,
    /Preserve unresolved questions explicitly/iu,
    /only those authorized answers/iu,
    /same revision\/invalidation\s+safeguards as `revise`/iu,
    /Reanalyze consistency and coverage after capture/iu,
    /Answers are not implementation approval/iu,
    /cannot broaden a running Auto grant/iu,
    /emits no telemetry, including answer\s+capture/iu,
  ],
  analyze: [
    /read-only consistency, coverage, and\s+requirements-quality review/iu,
    /manual semantic review may continue but must not claim\s+engine validation/iu,
    /Separate semantic judgments from deterministic findings/iu,
    /explicit capture scope and destination/iu,
    /Do not run project tests or any project-code execution/iu,
    /Never auto-check or approve reviewer-owned checklist items/iu,
    /Requirements-quality checklists are not executed-test evidence/iu,
    /emits no telemetry/iu,
  ],
  principles: [
    /`missionspec\/principles\.md`/u,
    /not Mission Context/iu,
    /creation only when explicitly requested/iu,
    /impact on active changes/iu,
    /explicit review of the project-wide patch/iu,
    /Principles grant no runtime permissions/iu,
    /blindly rewrite shared templates, generated skills, or host configuration/iu,
  ],
  sync: [
    /same synchronization used by\s+`archive`, not a weaker shortcut/iu,
    /Require current acceptance for the exact eligible deltas/iu,
    /same sync engine used by archive/iu,
    /original\/current\/accepted delta revisions by stable requirement\/scenario/iu,
    /explicit confirmation for\s+that preview/iu,
    /revalidate freshness, acceptance,\s+evidence policy, and conflicts/iu,
    /journaled multi-file mutation and recovery/iu,
    /recoverable partial state/iu,
    /Leave the\s+change open/iu,
    /do not create a closure record or move the change directory/iu,
  ],
  onboard: [
    /Explanation comes first/iu,
    /full\s+twelve-skill catalog/iu,
    /source assets alone do not prove installation/iu,
    /Every action stays separately authorized/iu,
    /Do not\s+auto-initialize, create Git branches, commit, push/iu,
    /Do not chain `draft-all` into implementation/iu,
    /Mission Context is an optional separately installed provider/iu,
    /no umbrella telemetry event/iu,
    /`effects: none`/u,
  ],
};

for (const id of ids) {
  test(`${id}: preserves operation-specific semantic safety sentinels (not compliance proof)`, () => {
    for (const sentinel of sentinels[id]) assert(sentinel.test(bodies[id]), `${id}: ${sentinel}`);
  });
}

test('drafting is not implementation; verification, acceptance, sync and closure have distinct effects', () => {
  for (const id of ['draft', 'draft-all', 'revise', 'clarify', 'analyze', 'principles']) {
    assert(!manifest.operations[id].effects.conditional.includes('project-check-execute'));
    assert(!manifest.operations[id].effects.conditional.includes('source-write'));
  }
  assert(!manifest.operations.verify.effects.conditional.includes('source-write'));
  assert(!manifest.operations.sync.effects.conditional.includes('closure-write'));
  assert(!manifest.operations.implement.effects.conditional.includes('acceptance-record'));
  assert.deepEqual(manifest.operations.onboard.effects.conditional, []);
  assert.deepEqual(
    ids.filter((id) => manifest.operations[id].telemetryClass === 'none'),
    ['discover', 'clarify', 'analyze', 'onboard'],
  );
});
