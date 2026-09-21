import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { LocalWorkflow, TerminalAuthority, openLocalAuthority, digestContent, digestApprovalRequest } from '../dist/api/index.js';

async function fixture(t, confirm) {
  const root = path.resolve(`.local-authority-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  // TEST ONLY correlated transport substitute. Production MCP must use its trusted SDK response, not test/model data.
  const transport = confirm === undefined ? undefined : {
    channel: 'mcp-elicitation', protocolIdentity: { id: 'test.mcp-form', version: '1' }, confirm,
  };
  const authority = await openLocalAuthority({ directory: root, ...(transport === undefined ? {} : { transport }) });
  const workflow = await LocalWorkflow.open(root, { authority });
  const plan = await workflow.previewSetup();
  return { root, authority, workflow, plan, transport };
}

test('missing, unsupported, cancelled, declined and malformed transport decisions never issue or bootstrap state', async (t) => {
  for (const decision of [undefined, 'unavailable', 'cancel', 'decline', true, { approved: true }, { action: 'accept' }]) {
    const f = await fixture(t, decision === undefined ? undefined : async () => decision);
    const result = await f.authority.confirmPlan(f.plan);
    assert.notEqual(result.value.state, 'issued');
    assert.deepEqual(await readdir(f.root), []);
  }
  const failed = await fixture(t, async () => { throw new Error('TEST disconnected client'); });
  assert.equal((await failed.authority.confirmPlan(failed.plan)).value.state, 'unavailable');
  assert.deepEqual(await readdir(failed.root), []);
});

test('transport receives detached deeply frozen exact review; backend persists before returning and terminal resolves it', async (t) => {
  let reviewed;
  let transportSignal;
  const f = await fixture(t, async (review, signal) => {
    reviewed = review;
    transportSignal = signal;
    assert.equal(signal.aborted, false);
    assert.equal(review.action, 'issue');
    assert.equal(review.approval, null);
    assert.equal(review.requestDigest, digestApprovalRequest(review.request));
    assert.equal(review.displayDigest, digestContent(JSON.stringify(review.display)));
    assert(review.renderedDisplay.includes('missionspec/config.yaml'));
    assert.equal(Date.parse(review.expiresAt) - Date.parse(review.deadlineAt), 28 * 60_000);
    assert(Object.isFrozen(review));
    assert(Object.isFrozen(review.request.binding));
    assert(Object.isFrozen(review.request.effects));
    assert(Object.isFrozen(review.display.detail.filePlan.mutations[0].effect));
    assert.throws(() => { review.request.effects[0].path = 'outside'; }, TypeError);
    assert.throws(() => { review.display.detail.previous.push({ path: 'fake' }); }, TypeError);
    return 'accept';
  });
  const result = await f.workflow.confirm(f.plan);
  assert.equal(result.value.state, 'issued');
  assert.equal(transportSignal.aborted, false);
  const approval = result.value.approval;
  assert.equal(approval.expiresAt, reviewed.expiresAt);
  assert.equal(approval.assurance.kind, 'local-user');
  assert.equal(approval.assurance.channel, 'mcp-elicitation');
  assert.deepEqual(approval.assurance.protocolIdentity, { id: 'test.mcp-form', version: '1' });
  assert.deepEqual(approval.assurance.qualification, { state: 'not-established' });
  assert.equal(approval.assurance.humanPresence, 'not-attested');
  assert.equal(approval.assurance.organizationIdentity, 'not-attested');
  const receipt = JSON.parse(await readFile(path.join(f.root, '.missionspec/approvals', `${approval.reference.id}.json`), 'utf8'));
  assert.equal(receipt.confirmation.id, reviewed.id);
  assert.equal(receipt.renderedDisplay, reviewed.renderedDisplay);
  assert.deepEqual(receipt.display, reviewed.display);
  const terminalRead = (await (await TerminalAuthority.open(f.root)).resolve(approval.reference)).value;
  assert.equal(terminalRead.state, 'current');
  assert.equal(terminalRead.approval.assurance.channel, 'mcp-elicitation');
  await f.workflow.apply(f.plan, approval.reference);
  assert.equal((await f.workflow.project()).state, 'initialized');
  const readerWithoutTransport = await openLocalAuthority({ directory: f.root });
  assert.equal((await readerWithoutTransport.resolve(approval.reference)).value.state, 'current');
});

test('root binding rejects foreign requests before callback, and JSON approval fields cannot issue authority', async (t) => {
  let called = 0;
  const f = await fixture(t, async () => { called++; return 'accept'; });
  const other = await fixture(t);
  await assert.rejects(f.authority.confirmPlan(other.plan), { code: 'scope-exceeded' });
  await assert.rejects(f.authority.requestConfirmation({ ...f.plan.request, approved: true }));
  await assert.rejects(openLocalAuthority({ directory: f.root, transport: { channel: 'qualified-host-callback', approved: true } }));
  assert.equal(called, 0);
  assert.deepEqual(await readdir(f.root), []);
});

test('request mutation during asynchronous confirmation cannot alter the reviewed grant', async (t) => {
  let accept;
  let reached;
  const ready = new Promise((resolve) => { reached = resolve; });
  const response = new Promise((resolve) => { accept = resolve; });
  const f = await fixture(t, async () => { reached(); return response; });
  const untrustedPlan = JSON.parse(JSON.stringify(f.plan));
  const pending = f.authority.confirmPlan(untrustedPlan);
  await ready;
  untrustedPlan.request.effects[0].proposed = digestContent('unreviewed bytes');
  untrustedPlan.mutations[0].content = 'unreviewed bytes';
  accept('accept');
  const issued = (await pending).value.approval;
  assert.equal(issued.requestDigest, digestApprovalRequest(f.plan.request));
  assert.notEqual(issued.request.effects[0].proposed, untrustedPlan.request.effects[0].proposed);
  await assert.rejects(f.workflow.apply(untrustedPlan, issued.reference));
  assert.equal((await f.workflow.project()).state, 'not-initialized');
});

test('deadline aborts correlated transport and ignores late acceptance without creating any grant', async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: Date.now() });
  let respond;
  let reached;
  let signal;
  const ready = new Promise((resolve) => { reached = resolve; });
  const response = new Promise((resolve) => { respond = resolve; });
  const f = await fixture(t, async (_review, abort) => { signal = abort; reached(); return response; });
  const pending = f.authority.confirmPlan(f.plan);
  await ready;
  t.mock.timers.tick(120_001);
  assert.equal((await pending).value.state, 'declined');
  assert.equal(signal.aborted, true);
  respond('accept');
  await Promise.resolve();
  assert.deepEqual(await readdir(f.root), []);
});

test('revocation is shared across transports and remains possible after one-time approval expiry', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = await fixture(t, async () => 'accept');
  const issued = (await f.authority.confirmPlan(f.plan)).value.approval;
  await f.workflow.apply(f.plan, issued.reference);
  t.mock.timers.tick(31 * 60_000);
  assert.equal((await f.authority.resolve(issued.reference)).value.state, 'expired');
  let reviewed;
  const another = await openLocalAuthority({ directory: f.root, transport: {
    ...f.transport, protocolIdentity: { id: 'test.second-form', version: '1' },
    confirm: async (review) => { reviewed = review; return 'accept'; },
  } });
  await another.revoke(issued.reference);
  assert.equal(reviewed.action, 'revoke');
  assert.deepEqual(reviewed.approval, issued.reference);
  assert.equal((await (await TerminalAuthority.open(f.root)).resolve(issued.reference)).value.state, 'revoked');
});

test('existing version-one terminal receipts remain readable without migration or transport-dependent identity', async (t) => {
  const f = await fixture(t, async () => 'accept');
  const issued = (await f.authority.confirmPlan(f.plan)).value.approval;
  // TEST ONLY legacy-format fixture; not a production record issuer.
  const approval = { ...issued, assurance: {
    kind: 'local-user', channel: 'terminal-confirmation', qualificationEvidence: digestContent('TEST ONLY prior terminal protocol'),
  } };
  const display = { request: issued.request, plan: f.plan,
    previous: f.plan.mutations.map((mutation) => ({ path: mutation.effect.path, before: null })),
    assurance: 'local-user only', expiresAfterMinutes: 30 };
  const content = JSON.stringify({ schemaVersion: 1, approval, display,
    displayDigest: digestContent(JSON.stringify(display)), renderedDisplay: JSON.stringify(display, null, 2) });
  const destination = path.join(f.root, '.missionspec/approvals', `${issued.reference.id}.json`);
  await writeFile(destination, content);
  const reader = await openLocalAuthority({ directory: f.root });
  const resolved = (await reader.resolve(issued.reference)).value;
  assert.equal(resolved.state, 'current');
  assert.deepEqual(resolved.approval.assurance.qualification, { state: 'not-established' });
  assert.equal(resolved.approval.assurance.protocolIdentity.id, 'missionspec.legacy-terminal');
  assert(!('qualificationEvidence' in resolved.approval.assurance));
  assert.equal(await readFile(destination, 'utf8'), content);
});

test('nested detail cannot replace the displayed request, action, expiry or transport assurance', async (t) => {
  const reviews = [];
  const f = await fixture(t, async (review) => { reviews.push(review); return 'accept'; });
  const setup = (await f.authority.confirmPlan(f.plan)).value.approval;
  await f.workflow.apply(f.plan, setup.reference);
  const actual = await f.workflow.previewNewChange({ slug: 'actual', specs: ['actual'] });
  const shadow = await f.workflow.previewNewChange({ slug: 'shadow', specs: ['shadow'] });
  const detail = {
    request: shadow.request, action: 'revoke', approval: { id: 'APR-chosen-by-client' },
    expiresAt: '2099-01-01T00:00:00.000Z', deadlineAt: '2099-01-01T00:00:00.000Z',
    assurance: { kind: 'organization', approved: true }, approved: true,
  };
  const issued = (await f.authority.requestConfirmation(actual.request, detail)).value.approval;
  const review = reviews.at(-1);
  assert.deepEqual(review.request, actual.request);
  assert.deepEqual(review.display.request, actual.request);
  assert.deepEqual(review.display.detail.request, shadow.request);
  assert.equal(review.display.action, 'issue');
  assert.equal(review.display.approval, null);
  assert.notEqual(review.display.expiresAt, detail.expiresAt);
  assert.equal(review.display.assurance.channel, 'mcp-elicitation');
  assert.equal(issued.requestDigest, digestApprovalRequest(actual.request));
  assert.notEqual(issued.reference.id, detail.approval.id);
  let getterCalls = 0;
  await assert.rejects(f.authority.requestConfirmation(actual.request, {
    get request() { getterCalls++; return shadow.request; },
  }));
  await assert.rejects(f.authority.requestConfirmation(actual.request, { toJSON() { return detail; } }));
  assert.equal(getterCalls, 0);
  const resolved = (await f.authority.resolve(issued.reference)).value;
  assert.equal(resolved.state, 'current');
  assert.deepEqual(resolved.approval.request, actual.request);
});

test('closed receipt validation rejects unknown fields, invalid dates, assurance claims, references and substituted displays', async (t) => {
  const f = await fixture(t, async () => 'accept');
  const issued = (await f.authority.confirmPlan(f.plan)).value.approval;
  const location = path.join(f.root, '.missionspec/approvals', `${issued.reference.id}.json`);
  const original = JSON.parse(await readFile(location, 'utf8'));
  const rerender = (value) => {
    value.displayDigest = digestContent(JSON.stringify(value.display));
    value.renderedDisplay = JSON.stringify(value.display, null, 2);
  };
  const other = await f.workflow.previewSetup('compact');
  const variants = [
    (value) => { value.approved = true; },
    (value) => { value.approval.extra = true; },
    (value) => { value.approval.reference.approved = true; },
    (value) => { value.approval.reference.id = 1; },
    (value) => { value.approval.contractVersion = 2; },
    (value) => { value.approval.state = 'current'; },
    (value) => { value.approval.issuedAt = 0; },
    (value) => { value.approval.issuedAt = '2026-02-30T00:00:00.000Z'; },
    (value) => { value.approval.issuedAt = '2026-09-20'; },
    (value) => { value.approval.expiresAt = value.approval.issuedAt; },
    (value) => { value.approval.assurance.qualification = { state: 'measured', digest: digestContent('descriptive wording') }; },
    (value) => { value.approval.assurance.humanPresence = 'attested'; },
    (value) => { value.approval.assurance.organizationIdentity = 'verified'; },
    (value) => { value.approval.assurance.protocolIdentity.version = 1; },
    (value) => { value.approval.assurance.protocolIdentity.qualification = true; },
    (value) => { value.approval.assurance.qualificationEvidence = digestContent('descriptive wording'); },
    (value) => { value.confirmation.extra = true; },
    (value) => { value.confirmation.deadlineAt = 0; },
    (value) => { value.confirmation.id = 'uncorrelated'; },
    (value) => { delete value.confirmation; },
    (value) => { value.display.extra = true; rerender(value); },
    (value) => { value.display.request = other.request; rerender(value); },
    (value) => { value.display.assurance.channel = 'terminal-confirmation'; rerender(value); },
    (value) => { value.display.approval = { id: 'APR-client' }; rerender(value); },
    (value) => { value.renderedDisplay += '\n'; },
  ];
  for (const [index, mutate] of variants.entries()) {
    const value = structuredClone(original);
    mutate(value);
    await writeFile(location, JSON.stringify(value));
    await assert.rejects(f.authority.resolve(issued.reference), { code: 'persistence-failed' }, `variant ${index}`);
  }
  await writeFile(location, JSON.stringify(original));
  assert.equal((await f.authority.resolve(issued.reference)).value.state, 'current');
  await assert.rejects(openLocalAuthority({ directory: f.root, transport: {
    ...f.transport, qualificationEvidence: digestContent('words cannot qualify a channel'),
  } }));
});

test('revocation records receive the same closed reference, timestamp and exact-display validation', async (t) => {
  const f = await fixture(t, async () => 'accept');
  const approval = (await f.authority.confirmPlan(f.plan)).value.approval;
  await f.workflow.apply(f.plan, approval.reference);
  await f.authority.revoke(approval.reference);
  const destination = path.join(f.root, '.missionspec/approvals', `${approval.reference.id}.revoked.json`);
  const original = JSON.parse(await readFile(destination, 'utf8'));
  for (const mutate of [
    (value) => { value.extra = true; },
    (value) => { value.reference.id = 'APR-another'; },
    (value) => { value.recordedAt = '2026-02-30T00:00:00.000Z'; },
    (value) => { value.review.approval.approved = true; },
    (value) => { value.review.display.request = { approved: true }; },
    (value) => { value.review.display.detail.issuedApproval.reference.id = 'APR-another'; },
  ]) {
    const value = structuredClone(original);
    mutate(value);
    await writeFile(destination, JSON.stringify(value));
    await assert.rejects(f.authority.resolve(approval.reference), { code: 'persistence-failed' });
  }
  await writeFile(destination, JSON.stringify(original));
  assert.equal((await f.authority.resolve(approval.reference)).value.state, 'revoked');
});
