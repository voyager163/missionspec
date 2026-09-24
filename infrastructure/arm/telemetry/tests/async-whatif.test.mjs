import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm, readdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { dirname, basename } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { buildPhase, ids, digest, json, BUDGET, RECEIVER_DIGEST, deploymentName } from '../definition.mjs';
import { verifyWhatIf } from '../policy.mjs';
import { asyncWhatIf, whatIfOperationUrl, whatIfRequestContext, authenticatedWhatIfRequest,
  load, saveImmutable, processFailureMetadata, safeOperationFailure, WHAT_IF_API, WHAT_IF_MAX_POLLS } from '../controller.mjs';

const c = { version: 2, subscriptionId: '00000000-0000-4000-8000-000000000001',
  tenantId: '00000000-0000-4000-8000-000000000002', operatorPrincipalId: '00000000-0000-4000-8000-000000000003',
  runId: '00000000-0000-4000-8000-000000000004', namePrefix: 'missionspec-test', registryName: 'missionspectest',
  location: 'australiaeast', budgetEmail: 'operator@example.invalid', budgetStart: '2026-09-01T00:00:00Z',
  budgetEnd: '2027-09-01T00:00:00Z', queryPrincipalIds: ['00000000-0000-4000-8000-000000000003'],
  receiverDigest: RECEIVER_DIGEST, budget: BUDGET, originSha256: digest('origin'),
  scannerAdoptionSha256: digest('scanner'), foundationBudgetsSha256: digest('budgets') };
const phase = buildPhase(c, 'core', null), context = whatIfRequestContext(c, phase), r = ids(c);
const opaque = `https://management.azure.com${r.sub}/operationresults/${'a'.repeat(364)}?api-version=${WHAT_IF_API}&t=${'1'.repeat(18)}&c=${'b'.repeat(2000)}&s=${'c'.repeat(342)}&h=${'d'.repeat(43)}`;
const regional = `https://management.azure.com${r.sub}/locations/australiaeast/operationresults/${c.runId}?api-version=${WHAT_IF_API}`;
const changes = phase.resources.map(v => ({ resourceId: v.id, changeType: 'Create' }));
function envelope(statusCode, body, headers = {}, action = 'start') {
  return { version: 1, statusCode, headers, body, bodyParseError: false, contextSha256: context.contextSha256,
    responseFile: 'whatif-response-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.json', step: `what-if.${action}`, verifiedRegion: c.location };
}
function harness(replies) {
  let now = Date.parse('2026-09-23T12:00:00.000Z'), cancelled = false;
  const requests = [], sleeps = [], traces = [];
  return {
    requests, sleeps, traces, get now() { return now; }, advance: ms => { now += ms; }, cancel: () => { cancelled = true; },
    options: { now: () => now, deadline: now + 120000, cancelled: () => cancelled,
      sleep: async ms => { sleeps.push(ms); now += ms; },
      record: async value => { traces.push(structuredClone(value)); },
      request: async operation => {
        operation.beforeDispatch();
        assert(operation.timeoutMs > 0 && operation.timeoutMs <= 15000 && operation.timeoutMs <= operation.deadlineMs - now);
        requests.push(operation); now += 1000;
        const reply = typeof replies === 'function' ? replies(operation, requests.length) : replies[requests.length - 1];
        assert(reply); return structuredClone(reply);
      } },
  };
}
test('documented202 Location is pinned to one start, then GETs produce the full200 result within the same deadline', async () => {
  const h = harness([
    envelope(202, null, { location: opaque, 'retry-after': '15' }),
    envelope(202, { status: 'Running' }, { 'retry-after': '2' }, 'poll'),
    envelope(200, { status: 'Succeeded', properties: { changes } }, {}, 'poll'),
  ]);
  const value = await asyncWhatIf(c, phase, 'unused', h.options);
  assert.deepEqual(value.result, { status: 'Succeeded', changes });
  verifyWhatIf(phase, value.result);
  assert.deepEqual(h.requests.map(v => v.action), ['start', 'poll', 'poll']);
  assert.equal(h.requests[1].pollUrl, opaque); assert.equal(h.requests[2].pollUrl, opaque);
  assert.equal(h.requests[1].initialResponseFile, 'whatif-response-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.json');
  assert.deepEqual(h.sleeps, [15000, 2000]);
  assert.equal(h.traces.at(-1).startPosts, 1);
  assert(!JSON.stringify(h.traces).includes(opaque), 'Tracing must retain only a handle hash, never the sensitive handle.');
  assert.equal(h.traces.at(-1).outcome, 'succeeded');
});
test('only the exact ARM result host/subscription/API and region or issued opaque context are accepted', () => {
  assert.equal(whatIfOperationUrl(c, opaque), opaque);
  assert.equal(whatIfOperationUrl(c, regional), regional);
  assert.equal(whatIfOperationUrl(c, regional.replace('https://management.azure.com', '')), regional);
  for (const value of [
    opaque.replace('management.azure.com', 'foreign.invalid'), opaque.replace('https:', 'http:'),
    opaque.replace('management.azure.com', 'user:password@management.azure.com'),
    opaque.replace('management.azure.com', 'management.azure.com:443'),
    opaque.replace(c.subscriptionId, c.tenantId), opaque.replace(WHAT_IF_API, '2022-09-01'),
    opaque + '#fragment', opaque + '&sig=credential', opaque + '&api-version=' + WHAT_IF_API,
    opaque.replace('/operationresults/', '/roleAssignments/'), opaque.replace('/operationresults/', '/operationresults/../operationresults/'),
    opaque.replace('operationresults', 'operation%72esults'), opaque.replace('t=' + '1'.repeat(18), 't=NaN'),
    opaque.replace('&h=' + 'd'.repeat(43), ''), opaque.replace('h=' + 'd'.repeat(43), 'h=short'),
    regional.replace('australiaeast', 'westus'), regional.replace(c.runId, ''), regional + '&unknown=x',
  ]) assert.throws(() => whatIfOperationUrl(c, value));
  assert.throws(() => whatIfOperationUrl(c, opaque.replace('h=' + 'd'.repeat(43), 'h=' + 'e'.repeat(43)), opaque), /HANDLE_CHANGED/);
});
test('missing Location, changed handles, redirects, malformed responses and unknown operation states fail closed', async () => {
  const cases = [
    [envelope(202, null)], [envelope(200, { status: 'Running' })],
    [envelope(202, null, { location: opaque, 'azure-asyncoperation': regional })],
    [envelope(302, null, { location: 'https://foreign.invalid' })],
    [{ ...envelope(200, null), bodyParseError: true }],
    [envelope(200, { status: 'Unknown' })],
    [envelope(202, { status: 'Unknown' }, { location: opaque })],
    [envelope(200, { status: 'Succeeded', properties: {} })],
    [envelope(200, { status: 'Succeeded', properties: { changes, nextLink: 'more' } })],
    [{ ...envelope(202, null, { location: opaque }), contextSha256: digest('other phase') }],
    [{ ...envelope(202, null, { location: opaque }), verifiedRegion: 'westus' }],
    [{ ...envelope(202, null, { location: opaque }), responseFile: undefined }],
    [envelope(202, null, { location: opaque }), envelope(202, null, { location: regional }, 'poll')],
  ];
  for (const replies of cases) {
    const h = harness(replies); await assert.rejects(asyncWhatIf(c, phase, 'unused', h.options));
    assert.equal(h.requests.filter(v => v.action === 'start').length, 1);
    assert.equal(h.traces.at(-1).outcome, 'failed');
  }
});
test('HTTP rejections and failed operations preserve bounded service codes without treating them as absence or timeout', async () => {
  for (const status of [400, 401, 403, 404, 409, 429, 500]) {
    const h = harness([envelope(status, { error: { code: 'AuthorizationFailed', message: 'private details' } })]);
    await assert.rejects(asyncWhatIf(c, phase, 'unused', h.options), e => e.message === 'WHAT_IF_HTTP_FAILED' && e.httpStatus === status && e.armCode === 'AuthorizationFailed');
    assert(!JSON.stringify(h.traces).includes('private details'));
  }
  for (const status of ['Failed', 'Canceled', 'Cancelled']) {
    const h = harness([envelope(200, { status, error: { code: 'DeploymentFailed', message: 'private details' } })]);
    await assert.rejects(asyncWhatIf(c, phase, 'unused', h.options), e => e.message === 'WHAT_IF_OPERATION_FAILED' && e.httpStatus === 200);
  }
});
test('Retry-After, poll count, cancellation and late observations cannot extend the shared absolute budget', async () => {
  for (const retry of ['-1', '1.5', 'Wed, 23 Sep 2026 00:00:00 GMT', '999999']) {
    const h = harness([envelope(202, null, { location: opaque, 'retry-after': retry })]);
    await assert.rejects(asyncWhatIf(c, phase, 'unused', h.options), /RETRY_AFTER/);
    assert.equal(h.requests.length, 1); assert.equal(h.sleeps.length, 0);
  }
  const capped = harness([envelope(202, null, { location: opaque, 'retry-after': '15' })]);
  capped.options.deadline = capped.now + 15000;
  await assert.rejects(asyncWhatIf(c, phase, 'unused', capped.options), /RETRY_AFTER_EXCEEDS_DEADLINE/);
  assert.equal(capped.sleeps.length, 0);
  const cancelSleep = harness([envelope(202, null, { location: opaque, 'retry-after': '1' })]);
  cancelSleep.options.sleep = async () => { cancelSleep.cancel(); };
  await assert.rejects(asyncWhatIf(c, phase, 'unused', cancelSleep.options), /WHAT_IF_CANCELLED/);
  assert.equal(cancelSleep.requests.length, 1);
  const cancelRecord = harness([]);
  cancelRecord.options.record = async () => { cancelRecord.cancel(); };
  await assert.rejects(asyncWhatIf(c, phase, 'unused', cancelRecord.options), /WHAT_IF_CANCELLED/);
  assert.equal(cancelRecord.requests.length, 0);
  const late = harness([envelope(200, { status: 'Succeeded', properties: { changes } })]);
  const original = late.options.request;
  late.options.request = async op => { const result = await original(op); late.advance(120000); return result; };
  await assert.rejects(asyncWhatIf(c, phase, 'unused', late.options), /DEADLINE_EXCEEDED/);
  const forever = harness(operation => envelope(202, null, operation.action === 'start' ? { location: opaque, 'retry-after': '0' } : { 'retry-after': '0' }, operation.action));
  await assert.rejects(asyncWhatIf(c, phase, 'unused', forever.options), /POLL_LIMIT/);
  assert.equal(forever.requests.length, WHAT_IF_MAX_POLLS);
  assert.equal(forever.requests.filter(v => v.action === 'start').length, 1);
});
test('the final result still goes through exact phase resource-change policy', async () => {
  const h = harness([envelope(200, { status: 'Succeeded', properties: { changes: [...changes, { resourceId: r.stateGroup, changeType: 'Delete' }] } })]);
  const result = await asyncWhatIf(c, phase, 'unused', h.options);
  assert.throws(() => verifyWhatIf(phase, result.result), /UNREVIEWED_RESOURCE_CHANGE/);
  for (const mutate of [
    p => { p.deploymentId += '-other'; }, p => { p.scope = r.stateGroup; },
    p => { p.template.resources[0].properties.unreviewed = '[listKeys(resourceId(), apiVersion)]'; },
    p => { p.template.templateLink = { uri: 'https://foreign.invalid' }; },
  ]) { const p = structuredClone(phase); mutate(p); assert.throws(() => whatIfRequestContext(c, p)); }
});
test('authenticated bridge writes private response files, avoids raw output and preserves typed process timeout evidence', async t => {
  const directory = `infrastructure/arm/telemetry/tests/.scratch-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  let guarded = false;
  const response = await authenticatedWhatIfRequest(context, directory, { action: 'start', pollUrl: null, initialResponseFile: null,
    timeoutMs: 15000, deadlineMs: Date.now() + 15000, beforeDispatch: () => { guarded = true; } },
  async (command, args, options) => {
    assert.equal(command, '/qualified/cli/python'); assert.equal(guarded, true);
    assert(options.timeout > 0 && options.timeout <= 15000);
    assert.equal(options.env.AZURE_CORE_COLLECT_TELEMETRY, 'false');
    assert.equal(options.env.AZURE_CLI_DISABLE_CONNECTION_VERIFICATION, undefined);
    const request = await load(dirname(args[3]), basename(args[3]));
    assert.equal(request.action, 'start'); assert.equal(request.scope, 'group');
    assert.equal(JSON.parse(request.body).location, undefined);
    await saveImmutable(dirname(args[4]), basename(args[4]), { ...envelope(200, { status: 'Succeeded', properties: { changes } }), responseFile: undefined });
    return { stdout: 'PRIVATE_WHATIF_RESPONSE_SAVED\n', stderr: '' };
  }, async () => '/qualified/cli/python');
  assert.equal(response.statusCode, 200);
  assert((await readdir(directory)).every(v => v.startsWith('whatif-request-') || v.startsWith('whatif-response-')));
  let executed = false;
  await assert.rejects(authenticatedWhatIfRequest(context, directory, { action: 'start', pollUrl: null, initialResponseFile: null,
    timeoutMs: 15000, deadlineMs: Date.now() + 15000, beforeDispatch: () => { throw new Error('WHAT_IF_CANCELLED'); } },
  async () => { executed = true; }, async () => '/qualified/cli/python'), /WHAT_IF_CANCELLED/);
  assert.equal(executed, false);
  const timeout = new Error('raw private argv and token'); Object.assign(timeout, { killed: true, signal: 'SIGTERM', code: null });
  const metadata = processFailureMetadata(timeout, 15000, 15004, 'deployment.group.what-if');
  assert.equal(metadata.kind, 'process-timeout'); assert.equal(metadata.timeoutObserved, true);
  const failure = new Error('ARM_OPERATION_FAILED'); failure.diagnostics = { ...metadata, rawArgs: ['secret'] }; failure.armCode = 'Unclassified';
  const safe = safeOperationFailure(failure);
  assert(!JSON.stringify(safe).includes('secret')); assert(!JSON.stringify(safe).includes('argv'));
  assert.equal(safe.diagnostics.signal, 'SIGTERM');
});
test('Python bridge rejects unsafe URLs and credential-bearing/static-expression inputs before authentication', async () => {
  const program = [
    'import importlib.util',
    's=importlib.util.spec_from_file_location(\"bridge\", \"infrastructure/arm/telemetry/arm-whatif.py\")',
    'm=importlib.util.module_from_spec(s); s.loader.exec_module(m)',
    `valid=${JSON.stringify(opaque)}`,
    `assert m.poll_url(valid, ${JSON.stringify(c.subscriptionId)}, \"australiaeast\")==valid`,
    'bad=[valid.replace(\"management.azure.com\", \"foreign.invalid\"),valid+\"&sig=secret\",valid+\"#fragment\",valid.replace(\"https:\",\"http:\")]',
    'for value in bad:',
    ' try: m.poll_url(value, \"' + c.subscriptionId + '\", \"australiaeast\"); raise AssertionError(\"accepted unsafe URL\")',
    ' except m.Stop: pass',
    'try: m.static_template({\"properties\":{\"key\":\"[listKeys()]\"}}); raise AssertionError(\"accepted expression\")',
    'except m.Stop: pass',
    'print(\"BRIDGE_VALIDATORS_PASSED_NO_AUTH_OR_NETWORK\")',
  ].join('\n');
  const result = await promisify(execFile)('python3', ['-I', '-B', '-c', program], { timeout: 10000 });
  assert.equal(result.stdout.trim(), 'BRIDGE_VALIDATORS_PASSED_NO_AUTH_OR_NETWORK');
});

test('Python and Node derive toggle and image-change names from the bound UUID, never the collector runId', async () => {
  const instance = { version: 1, id: '00000000-0000-4000-8000-000000000099', predecessorSha256: digest('prior'), previousInstanceIds: [] };
  const requests = ['synthetic-admission', 'synthetic-disable', 'disabled-image-upgrade', 'disabled-image-rollback'].map(name => {
    const p = { ...phase, phase: name, windowInstance: instance,
      deploymentId: `${r.group}/providers/Microsoft.Resources/deployments/${deploymentName(c, name, instance)}` };
    const request = whatIfRequestContext(c, p);
    return { request, expectedName: deploymentName(c, name, instance) };
  });
  const program = [
    'import importlib.util,json,hashlib',
    's=importlib.util.spec_from_file_location("bridge","infrastructure/arm/telemetry/arm-whatif.py")',
    'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)',
    `values=json.loads(${JSON.stringify(JSON.stringify(requests))})`,
    'for value in values:',
    ' request=value["request"]',
    ' assert m.fixed_deployment_name(request)==value["expectedName"]',
    ' fields=("subscriptionId","tenantId","location","namePrefix","runId","phase","scope","phaseSha256","bodySha256","windowInstanceId","predecessorSha256")',
    ' assert hashlib.sha256("\\n".join("" if request[k] is None else str(request[k]) for k in fields).encode()).hexdigest()==request["contextSha256"]',
    ' for key,new in [("windowInstanceId",None),("windowInstanceId",request["runId"]),("predecessorSha256","bad")]:',
    '  changed=dict(request);changed[key]=new',
    '  try:m.fixed_deployment_name(changed);raise AssertionError("accepted invalid instance")',
    '  except m.Stop:pass',
    'print("BOUND_WINDOW_NAMES_MATCH_NO_AUTH_OR_NETWORK")',
  ].join('\n');
  const result = await promisify(execFile)('python3', ['-I', '-B', '-c', program], { timeout: 10000 });
  assert.equal(result.stdout.trim(), 'BOUND_WINDOW_NAMES_MATCH_NO_AUTH_OR_NETWORK');
});
