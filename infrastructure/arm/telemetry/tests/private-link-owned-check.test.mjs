import assert from 'node:assert/strict';
import test from 'node:test';
import { registerHooks } from 'node:module';
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { mkdir, readdir, rm } from 'node:fs/promises';

const controllerUrl = new URL('../private-link-controller.mjs', import.meta.url).href;
const helperUrl = new URL('../private-link.mjs', import.meta.url).href;
const hooks = registerHooks({
  load(url, context, next) {
    const loaded = next(url, context);
    if (![controllerUrl, helperUrl].includes(url)) return loaded;
    let source = loaded.source.toString();
    if (url === controllerUrl) {
      const adapter = 'const io = privateLinkAzureIO(c, context, snapshot.evidence, snapshot.phase, directory, inputs, options.invoke ?? az, options);';
      const retained = 'await savePrivateLinkArtifact(directory, `private-link-${stage}-preflight.json`, proof);\n      checkInputs();';
      assert.equal(source.split(adapter).length, 2);
      assert.equal(source.split(retained).length, 2);
      source = source.replace(adapter, adapter + '\n      testObserve?.({ boundary: "adapter", io, snapshot, validation, state, evidence, phase, checkInputs, c, context });')
        .replace(retained, retained.replace('\n      checkInputs();',
          '\n      await testObserve?.({ boundary: "fixed-retention", io, snapshot, validation, state, evidence, phase, checkInputs, c, context });\n      checkInputs();'));
      source += '\nlet testObserve; export const setTestObserve = fn => { testObserve = fn; };\n' +
        'export const testValidationActive = value => dispatchValidations.has(value);\n';
    } else {
      source += '\nexport const testAssignedPrefix = value => assignedPrefixHashes.get(value);\n';
    }
    return { ...loaded, source };
  },
});
// Inspection exists only in this worker's loader output, not production files,
// exports, options, or serialized validation tokens.
const [control, helper, definition, fixture, nsg, runtimeFixture] = await Promise.all([
  import('../private-link-controller.mjs'), import('../private-link.mjs'), import('../definition.mjs'),
  import('./private-link.fixture.mjs'), import('./private-link-nsg-adoption.fixture.mjs'),
  import('./private-link-runtime.fixture.mjs'),
]);
hooks.deregister();
const { digestJson: hash } = definition;
const observed = new AsyncLocalStorage();
control.setTestObserve(event => observed.getStore()?.observe(event));
const x = await nsg.nsgAdoptionFixture(() => {}, true);
const f = { ...x.f, at: x.io.now() + 1000 };
const chain = structuredClone(x.adoptedEvidence);
for (const stage of helper.PRIVATE_LINK_CONTROL_STAGES.slice(6, 13)) {
  const h = await fixture.privateControlHarness(f, chain, stage, {
    snapshot: value => nsg.adoptedSnapshot(x, value), configureIO: value => nsg.adoptedIO(x, value),
  });
  chain.records.push(await h.execute());
  f.at += 1000;
}
const names = { version: 1, action: 'use-reviewed-private-link-runtime-names',
  decision: 'use-two-shortened-runtime-names', configSha256: hash(f.c), planSha256: f.context.plan.planSha256,
  originSha256: hash(f.context.origin), controlEvidenceSha256: hash(chain), ...helper.privateLinkRuntimeNameIds(f.c),
  sourceSha256: f.source, publication: { commitSha: 'e'.repeat(40), sourceSha256: f.source },
  approvedAt: new Date(f.at - 1).toISOString(), expiresAt: new Date(f.at + 1800000).toISOString() };
const cost = fixture.privateCostFixture(f);
const runtimeReview = { policyRevision: null, costReview: cost.review, costEvidence: cost.evidence, nameProjection: names };
const prerequisites = control.verifyPrivateLinkRuntimePrerequisites(f.c, f.context, chain, f.at);
const completed = await runtimeFixture.privateRuntimeCompletionFixture(f, chain, prerequisites, { runtimeReview });
f.at = completed.at + 1000;
const stage = 'retire-old-receiver';
function project(snapshot) {
  nsg.adoptedSnapshot(x, snapshot);
  for (const [key, app] of [['app', completed.completion.disable.observation.app], ['publicProbe', null]]) {
    snapshot.resources[names.original[key]] = null;
    snapshot.resources[names.projected[key]] = structuredClone(app);
    delete snapshot.diagnostics[names.original[key]];
    snapshot.diagnostics[names.projected[key]] = { value: [] };
  }
  for (const key of ['apps', 'groupResources']) {
    snapshot.lists[key].value = snapshot.lists[key].value.filter(value =>
      ![...Object.values(names.original), ...Object.values(names.projected)].includes(value.id));
    snapshot.lists[key].value.push(structuredClone(completed.completion.disable.observation.app));
  }
  snapshot.images.manifests = structuredClone(completed.completion.candidate.publication.manifests);
  snapshot.images.queueManifest = JSON.parse(completed.completion.candidate.profile.manifestJson);
}
const base = await fixture.privateControlHarness(f, chain, stage, {
  runtimeCompletion: completed.completion, snapshot: project,
  configureIO: io => { nsg.adoptedIO(x, io); io.nameProjection = names; io.projectionEvidence = chain; },
});

async function harness(t, { noNsg = false } = {}) {
  const evidence = structuredClone(noNsg ? x.evidence : chain);
  const selectedStage = noNsg ? 'create-environment' : stage;
  const setup = noNsg ? await fixture.privateControlHarness(x.f, evidence, selectedStage) : base;
  const suffix = `owned-${randomUUID().replaceAll('-', '').slice(0, 24)}`;
  assert(suffix.length <= 32);
  const directory = `infrastructure/arm/telemetry/.operator-private/revision-20261008-${suffix}`;
  const key = control.privateLinkTargetKey(f.context), terminal = evidence.records.at(-1);
  const files = new Map([
    [`private-link-head-${key}.json`, control.privateLinkHead(f.context, evidence)],
    [`private-link-fence-${key}.json`, { version: 1, targetKey: key, stage: terminal.stage,
      phase: terminal.phase, intent: terminal.intent, intentSha256: terminal.intentSha256 }],
    [`private-link-intent-${hash({ target: key, stage: terminal.stage })}.json`, { phase: terminal.phase, intent: terminal.intent }],
    [`private-link-nsg-adoption-${key}.json`, evidence.externalAdoption],
  ]);
  let now = noNsg ? x.f.at : f.at, source = f.source, cancelled = false, capture;
  let onBoundary = async () => {}, cloudReads = 0;
  const input = { publication: structuredClone(setup.io.publication), costReview: structuredClone(setup.io.costReview),
    costEvidence: structuredClone(setup.io.costEvidence), migrationReview: structuredClone(setup.io.migrationReview),
    ...(noNsg ? {} : { nameProjection: structuredClone(names), runtimeCompletion: structuredClone(completed.completion) }) };
  const invoke = nsg.retainedReadInvoke(f, setup.before, setup.io.read);
  const options = {
    now: () => now, cancelled: () => cancelled,
    sourceDigest: async () => { await onBoundary('source'); return source; },
    lookup: nsg.retainedSourceLookup(f.context, evidence, input, completed.completion),
    invoke: async (...args) => { cloudReads++; const value = await invoke(...args); await onBoundary('current'); return value; },
    store: { root: directory, read: async (_root, name) => {
      const value = structuredClone(files.get(name) ?? null);
      if (name.startsWith('private-link-head-')) await onBoundary('head');
      return value;
    }, save: async () => assert.fail('CHECK cannot update ledger'),
    saveImmutable: async () => assert.fail('CHECK cannot reserve or append') },
  };
  const state = {
    evidence, input, options, files, key, directory,
    setNow: value => { now = value; }, get now() { return now; },
    setSource: value => { source = value; }, cancel: () => { cancelled = true; },
    boundary: fn => { onBoundary = fn; },
    get capture() { return capture; }, get cloudReads() { return cloudReads; },
    observe: async event => {
      if (event.boundary === 'adapter') {
        capture = event;
        if (!noNsg) {
          assert.notEqual(event.evidence, event.snapshot.evidence);
          assert.equal(event.io.projectionEvidence, event.snapshot.evidence);
          assert.equal(event.state.evidence, event.snapshot.evidence);
          assert.equal(Object.isFrozen(event.snapshot.evidence), true);
          assert.equal(helper.testAssignedPrefix(event.snapshot.evidence), hash(event.snapshot.evidence));
          assert.equal(helper.testAssignedPrefix(event.evidence), undefined);
        } else {
          assert.equal(event.state, null);
          assert.equal(event.snapshot.evidence, evidence);
        }
        const retain = event.io.retain;
        event.io.retain = async (...args) => {
          await retain(...args);
          if (args[0] === 'preflight') await onBoundary('uuid-retention');
        };
        if (noNsg) event.io.preview = setup.io.preview;
      } else await onBoundary('fixed-retention');
    },
    run: () => observed.run(state, () => control.runPrivateLinkControl(f.c, f.context, evidence,
      selectedStage, 'check', directory, input, options)),
  };
  await mkdir('infrastructure/arm/telemetry/.operator-private', { recursive: true, mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  return state;
}

test('default CHECK uses exact owned adapter evidence and retains both preflights within a closed scope', async t => {
  const q = await harness(t), callerHash = hash(q.evidence);
  const proof = await q.run();
  assert.equal(proof.kind, 'checked-private-link-phase');
  assert.equal((await readdir(q.directory)).filter(name => name.includes('preflight')).length, 2);
  assert.equal(hash(q.evidence), callerHash);
  assert.equal(Object.isFrozen(q.evidence), false);
  assert.equal(helper.testAssignedPrefix(q.capture.snapshot.evidence), undefined);
  assert.equal(control.testValidationActive(q.capture.validation), false);
  assert(q.cloudReads > 0);
});

test('default CHECK rejects caller evidence, ordered keys, adoption, record and phase changes across awaits', async t => {
  const mutations = [
    ['evidence replacement member', q => { q.evidence.records = q.evidence.records.slice(0, -1); }],
    ['evidence key order', q => {
      const first = Object.keys(q.evidence)[0], value = q.evidence[first];
      delete q.evidence[first]; q.evidence[first] = value;
    }],
    ['adoption replacement', q => { q.evidence.externalAdoption = { ...q.evidence.externalAdoption, version: 99 }; }],
    ['record member', q => { q.evidence.records.at(-1).authority.ingestionAuthorized = true; }],
    ['phase member', q => { q.capture.phase.request.id += '-changed'; }],
    ['phase key order', q => {
      const phase = q.capture.phase, first = Object.keys(phase)[0], value = phase[first];
      delete phase[first]; phase[first] = value;
    }],
  ];
  for (const boundary of ['source', 'head', 'current', 'uuid-retention', 'fixed-retention']) {
    for (const [name, mutate] of mutations) await t.test(`${boundary}: ${name}`, async t => {
      const q = await harness(t);
      let changed = false;
      q.boundary(async point => {
        if (point !== boundary || changed) return;
        changed = true; await Promise.resolve(); mutate(q);
      });
      await assert.rejects(q.run(), /DISPATCH_VALIDATION_CHANGED|PRIVATE_LINK_NSG_CANONICAL_ADOPTION_REQUIRED/);
      assert(changed);
      assert.equal(helper.testAssignedPrefix(q.capture.snapshot.evidence), undefined);
      assert.equal(control.testValidationActive(q.capture.validation), false);
    });
  }
});

test('default CHECK keeps source, publication, names, head, runtime, cancellation and clocks live', async t => {
  for (const [name, boundary, mutate, failure] of [
    ['source drift', 'current', q => q.setSource('0'.repeat(64)), /SOURCE|CHECK_EXPIRED/],
    ['publication replacement', 'source', q => { q.input.publication.sourceSha256 = '0'.repeat(64); }, /PUBLISHED_SOURCE/],
    ['name expires during collection', 'current', q => q.setNow(Date.parse(q.input.nameProjection.expiresAt)), /EXPIRED|DEADLINE/],
    ['changed name prefix', 'source', q => { q.input.nameProjection.controlEvidenceSha256 = '0'.repeat(64); }, /NAME_REVIEW_CHANGED|NAME_PREFIX_CHANGED/],
    ['head drift', 'current', q => q.files.set(`private-link-head-${q.key}.json`, {}), /HEAD_CHANGED/],
    ['runtime completion swap', 'current', q => { q.input.runtimeCompletion = {}; }, /RUNTIME_QUALIFICATION_CHANGED/],
    ['cancel after UUID retention', 'uuid-retention', q => q.cancel(), /CHECK_EXPIRED/],
    ['deadline after fixed retention', 'fixed-retention', q => q.setNow(q.now + 120000), /CHECK_EXPIRED/],
    ['cost expires after fixed retention', 'fixed-retention', q => { q.input.costReview.expiresAt = new Date(q.now).toISOString(); }, /REVIEW_EXPIRED/],
  ]) await t.test(name, async t => {
    const q = await harness(t); let changed = false;
    q.boundary(async point => { if (point === boundary && !changed) { changed = true; await Promise.resolve(); mutate(q); } });
    await assert.rejects(q.run(), failure);
    assert(changed);
  });
});

test('default CHECK scope isolation preserves concurrent and no-NSG/direct compatibility', async t => {
  const first = await harness(t), second = await harness(t);
  await Promise.all([first.run(), second.run()]);
  assert.notEqual(first.capture.snapshot.evidence, second.capture.snapshot.evidence);
  assert.notEqual(first.capture.validation, second.capture.validation);
  for (const q of [first, second]) {
    assert.equal(control.testValidationActive(q.capture.validation), false);
    assert.equal(helper.testAssignedPrefix(q.capture.snapshot.evidence), undefined);
  }
  const legacy = await harness(t, { noNsg: true });
  assert.equal((await legacy.run()).kind, 'checked-private-link-phase');
  const direct = await fixture.privateControlHarness(x.f, structuredClone(x.evidence), 'create-environment');
  const proof = await control.checkPrivateLinkPhase(x.f.c, x.f.context, x.evidence, direct.phase, direct.io);
  assert.equal(proof.kind, 'checked-private-link-phase');
});

test('the final original-input comparison remains inside the last clock and cancellation guard', async t => {
  for (const [name, change] of [
    ['comparison consumes remaining deadline', q => q.setNow(q.now + 120000)],
    ['comparison observes cancellation', q => q.cancel()],
  ]) await t.test(name, async t => {
    const q = await harness(t), before = hash(q.evidence);
    let checks = 0, applied = false;
    q.boundary(async boundary => {
      if (boundary !== 'fixed-retention') return;
      const compare = q.capture.state.checkCallerInputs;
      q.capture.state.checkCallerInputs = () => {
        compare();
        if (++checks === 2) { change(q); applied = true; }
      };
    });
    await assert.rejects(q.run(), /PRIVATE_LINK_CHECK_EXPIRED/);
    assert(applied, 'the final comparison must be reached, not an earlier guard');
    assert.equal(checks, 2);
    assert.equal(hash(q.evidence), before, 'clock/cancellation changes do not mutate the caller graph');
    assert.equal((await readdir(q.directory)).filter(name => name.includes('preflight')).length, 2);
  });
});
