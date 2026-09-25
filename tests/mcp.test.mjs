import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMissionSpecMcpServer } from '../dist/mcp/server.js';
import { digestApprovalRequest, digestContent } from '../dist/api/index.js';
import { createMcpWorkflows } from '../dist/mcp/workflows.js';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { loadPackagedSkillCatalog } from '../dist/adapters/packaged-assets/skills.js';

async function fixture(context, reviewer) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'missionspec-mcp-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  const server = await createMissionSpecMcpServer({ root, version: '0.0.0', reviewer });
  const client = new Client({ name: 'TEST-client-not-user-identity', version: '0.0.0' }, { capabilities: {} });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  context.after(async () => { await client.close(); await server.close(); });
  return { root, server, client };
}

test('real MCP protocol negotiation exposes bounded read-only tools without initializing a workspace', async (context) => {
  const f = await fixture(context);
  const listed = await f.client.listTools();
  assert.equal(listed.tools.length, 13);
  assert(listed.tools.every((tool) => tool.annotations.readOnlyHint === true && tool.inputSchema.additionalProperties === false));
  const result = await f.client.callTool({ name: 'missionspec_project_status', arguments: {} });
  assert.equal(result.structuredContent.value.state, 'not-initialized');
  assert.deepEqual(await readdir(f.root), []);
});

test('MCP skill projections keep host syntax distinct and never claim installation', async (context) => {
  const f = await fixture(context);
  const listed = await f.client.callTool({ name: 'missionspec_skill', arguments: {} });
  assert.equal(listed.structuredContent.value.length, 12);
  const rendered = await f.client.callTool({ name: 'missionspec_skill', arguments: { operation: 'draft', host: 'codex' } });
  assert.equal(rendered.structuredContent.value.installed, false);
  assert(rendered.structuredContent.value.content.includes('$missionspec-draft'));
});

test('tool arguments cannot widen the root, inject approval, or leak rejected secret input', async (context) => {
  const f = await fixture(context);
  const marker = 'PRIVATE-REJECTED-INPUT';
  for (const argumentsValue of [
    { root: '../outside', approved: true, secret: marker },
    { change: '../outside', secret: marker },
  ]) {
    const result = await f.client.callTool({ name: 'missionspec_status', arguments: argumentsValue });
    assert.equal(result.isError, true);
    assert(!JSON.stringify(result).includes(marker));
    assert.equal(result.structuredContent.error.code, 'invalid-input');
  }
  assert.deepEqual(await readdir(f.root), []);
});

test('unknown tools and unavailable changes return explicit MCP failures, not empty successes', async (context) => {
  const f = await fixture(context);
  const missing = await f.client.callTool({ name: 'missionspec_status', arguments: { change: 'missing' } });
  assert.equal(missing.isError, true);
  const unknown = await f.client.callTool({ name: 'PRIVATE-UNKNOWN-NAME', arguments: {} });
  assert.equal(unknown.isError, true);
  assert(!JSON.stringify(unknown).includes('PRIVATE-UNKNOWN-NAME'));
});

test('invalid document validation is an explicit MCP error with bounded safe diagnostics', async (context) => {
  const f = await fixture(context);
  await writeFile(path.join(f.root, 'invalid.md'), 'PRIVATE-INVALID-DOCUMENT-CONTENT');
  const invalid = await f.client.callTool({ name: 'missionspec_validate', arguments: { paths: ['invalid.md'] } });
  assert.equal(invalid.isError, true);
  assert.equal(invalid.structuredContent.status, 'failed');
  assert.equal(invalid.structuredContent.value.state, 'invalid');
  assert(!JSON.stringify(invalid).includes('PRIVATE-INVALID-DOCUMENT-CONTENT'));
  assert.deepEqual(await readdir(f.root), ['invalid.md']);
});

// An injected synthetic channel exercises routing, not human/host qualification.
function testReviewer() {
  const approvals = new Map();
  const reviewed = [];
  return {
    reviewed, decline: false,
    async resolve(reference) {
      const approval = approvals.get(reference.id);
      return { status: 'ok', value: approval === undefined ? { state: 'absent', reference } : { state: 'current', approval } };
    },
    async requestConfirmation(request, detail) {
      reviewed.push({ request, detail });
      if (this.decline) return { status: 'ok', value: { state: 'declined' } };
      const now = Date.now();
      const approval = {
        contractVersion: 1, state: 'trusted-issued', reference: { id: `APR-${randomUUID()}` },
        assurance: {
          kind: 'local-user', channel: 'qualified-host-callback',
          qualificationEvidence: digestContent('TEST fixture only: no human or coding-host qualification'),
        },
        request, requestDigest: digestApprovalRequest(request),
        issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString(),
      };
      approvals.set(approval.reference.id, approval);
      return { status: 'ok', value: { state: 'issued', approval } };
    },
    async confirmPlan(plan) { return this.requestConfirmation(plan.request, { plan }); },
  };
}

const preview = async (client, action) => client.callTool({ name: 'missionspec_preview', arguments: { action } });
const apply = async (client, preview) => client.callTool({ name: 'missionspec_apply', arguments: { preview } });

test('workflow previews are read-only and do not advertise an issuer without trusted composition', async (context) => {
  const f = await fixture(context);
  const result = await preview(f.client, { kind: 'setup' });
  assert.equal(result.structuredContent.value.authorityIssued, false);
  assert.match(result.structuredContent.value.preview, /^[a-f0-9]{48}$/u);
  assert.deepEqual(await readdir(f.root), []);
  assert.equal((await apply(f.client, result.structuredContent.value.preview)).isError, true);
  assert(!(await f.client.listTools()).tools.some((tool) => tool.name === 'missionspec_apply'));
});

test('one-use preview routes full plan to independent authority and commits through shared transaction guards', async (context) => {
  const reviewer = testReviewer();
  const f = await fixture(context, reviewer);
  const prepared = await preview(f.client, { kind: 'setup', hosts: ['codex'] });
  assert.notEqual(prepared.isError, true, JSON.stringify(prepared));
  assert.deepEqual(await readdir(f.root), []);
  const token = prepared.structuredContent.value.preview;
  const applied = await apply(f.client, token);
  assert.notEqual(applied.isError, true, JSON.stringify(applied));
  assert.equal(reviewer.reviewed.length, 1);
  assert.equal(reviewer.reviewed[0].detail.plan.mutations.filter((mutation) => mutation.effect.path.endsWith('/SKILL.md')).length, 12);
  const replay = await apply(f.client, token);
  assert.equal(replay.structuredContent.error.code, 'not-found');
  assert.equal(reviewer.reviewed.length, 1);
  const status = await f.client.callTool({ name: 'missionspec_project_status', arguments: {} });
  assert.equal(status.structuredContent.value.state, 'initialized');
  const inspected = await f.client.callTool({ name: 'missionspec_skills_inspect', arguments: { hosts: ['codex'] } });
  assert.equal(inspected.structuredContent.value.files.length, 12);
  assert(inspected.structuredContent.value.files.every((file) => file.state === 'current'));
});

test('declined, forged and stale previews never acquire broader effects', async (context) => {
  const reviewer = testReviewer();
  reviewer.decline = true;
  const f = await fixture(context, reviewer);
  const prepared = await preview(f.client, { kind: 'setup' });
  const token = prepared.structuredContent.value.preview;
  const injected = await f.client.callTool({
    name: 'missionspec_apply', arguments: { preview: token, approved: true, approval: 'APR-forged' },
  });
  assert.equal(injected.structuredContent.error.code, 'invalid-input');
  assert.equal(reviewer.reviewed.length, 0);
  assert.equal((await apply(f.client, token)).structuredContent.error.code, 'authority-required');
  assert.deepEqual(await readdir(f.root), []);
  reviewer.decline = false;
  const stale = await preview(f.client, { kind: 'setup' });
  await writeFile(path.join(f.root, '.gitignore'), '# User edit after preview\n');
  assert.equal((await apply(f.client, stale.structuredContent.value.preview)).structuredContent.error.code, 'stale-revision');
  assert.deepEqual(await readdir(f.root), ['.gitignore']);
});

test('pending previews are bounded and may be discarded without project writes', async (context) => {
  const f = await fixture(context);
  let token;
  for (let index = 0; index < 16; index += 1) {
    const result = await preview(f.client, { kind: 'setup' });
    assert.notEqual(result.isError, true);
    token = result.structuredContent.value.preview;
  }
  assert.equal((await preview(f.client, { kind: 'setup' })).structuredContent.error.code, 'limit-reached');
  await f.client.callTool({ name: 'missionspec_discard_preview', arguments: { preview: token } });
  assert.notEqual((await preview(f.client, { kind: 'setup' })).isError, true);
  assert.deepEqual(await readdir(f.root), []);
});

test('cancellation during independent review fences a late decision before any file effect', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'missionspec-mcp-cancel-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  const reviewer = testReviewer();
  let release;
  let reviewing;
  const started = new Promise((resolve) => { reviewing = resolve; });
  const released = new Promise((resolve) => { release = resolve; });
  reviewer.confirmPlan = async (plan) => {
    reviewing();
    await released;
    return reviewer.requestConfirmation(plan.request);
  };
  const workflow = await LocalWorkflow.open(root, { authority: reviewer });
  const operations = createMcpWorkflows(workflow, await loadPackagedSkillCatalog(), '0.0.0', reviewer);
  const prepared = await operations.preview({ action: { kind: 'setup' } });
  const cancellation = new AbortController();
  const applied = operations.apply({ preview: prepared.preview }, cancellation.signal);
  await started;
  cancellation.abort();
  release();
  await assert.rejects(applied, { code: 'authority-required' });
  assert.deepEqual(await readdir(root), []);
  await assert.rejects(operations.apply({ preview: prepared.preview }), { code: 'not-found' });
});

test('MCP artifact flow enforces one-node scope, prerequisite order and the draft-all implementation stop', async (context) => {
  const f = await fixture(context, testReviewer());
  const commit = async (action) => {
    const prepared = await preview(f.client, action);
    assert.notEqual(prepared.isError, true, JSON.stringify(prepared));
    const result = await apply(f.client, prepared.structuredContent.value.preview);
    assert.notEqual(result.isError, true, JSON.stringify(result));
    return prepared.structuredContent.value.review;
  };
  await commit({ kind: 'setup' });
  await commit({
    kind: 'new-change', change: 'filters', specs: ['filters', 'reset'],
    sourcePaths: ['src/filter-preference.ts', 'tests/filter-preference.test.ts'],
  });
  const status = await f.client.callTool({ name: 'missionspec_status', arguments: { change: 'filters' } });
  const id = status.structuredContent.value.changeId;
  const drafts = {};
  for (const artifact of ['proposal', 'specs', 'design', 'tasks']) {
    const examples = artifact === 'specs' ? ['specs/filters.md', 'specs/reset.md'] : [`${artifact}.md`];
    drafts[artifact] = await Promise.all(examples.map(async (example) => ({
      path: `missionspec/changes/filters/${example.startsWith('specs/') ? example.replace(/\.md$/u, '/spec.md') : example}`,
      content: (await readFile(new URL(`../assets/workflows/standard/examples/${example}`, import.meta.url), 'utf8')).replaceAll('CHG-remember-filter', id),
    })));
  }
  const premature = await preview(f.client, { kind: 'artifact', change: 'filters', artifact: 'tasks', mode: 'capture', files: drafts.tasks });
  assert.equal(premature.isError, true);
  const mixed = await preview(f.client, { kind: 'artifact', change: 'filters', artifact: 'proposal', mode: 'capture', files: [...drafts.proposal, ...drafts.design] });
  assert.equal(mixed.isError, true);
  const proposal = await commit({ kind: 'artifact', change: 'filters', artifact: 'proposal', mode: 'capture', files: drafts.proposal });
  assert.equal(proposal.mutations.filter((mutation) => mutation.effect.purpose === 'artifact').length, 1);
  const batch = await commit({ kind: 'draft-all', change: 'filters', drafts });
  assert.equal(batch.implementationStarted, false);
  assert.deepEqual(batch.completed, ['specs', 'design', 'tasks']);
  const ready = await f.client.callTool({ name: 'missionspec_status', arguments: { change: 'filters' } });
  assert.equal(ready.structuredContent.value.implementationReady, true);
  const patch = await commit({
    kind: 'source-patch', change: 'filters', task: 'TSK-filter',
    proposal: {
      kind: 'inert-proposal', host: 'codex', summary: 'Original test candidate, not a host execution.',
      changes: [{ path: 'src/filter-preference.ts', expected: 'absent', content: 'export const fixture = true;\n' }],
    },
  });
  assert.equal(patch.request.purpose, 'source-apply');
  assert.equal(await readFile(path.join(f.root, 'src/filter-preference.ts'), 'utf8'), 'export const fixture = true;\n');
  const closure = await commit({ kind: 'archive', change: 'filters', outcome: 'incomplete' });
  const outcome = closure.mutations.find((mutation) => mutation.effect.path.endsWith('/closure.json'));
  assert.equal(JSON.parse(outcome.content).outcome, 'incomplete');
  assert.equal(JSON.parse(outcome.content).acceptance, null);
});

test('real stdio child remains protocol-clean and read-only through negotiation, preview and shutdown', { timeout: 15_000 }, async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'missionspec-mcp-stdio-'));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('../dist/cli/main.js', import.meta.url)), 'mcp'],
    stderr: 'pipe',
    cwd: root,
    env: { MISSIONSPEC_TELEMETRY: '0', DO_NOT_TRACK: '1' },
  });
  const client = new Client({ name: 'TEST-stdio', version: '0.0.0' }, { capabilities: {} });
  context.after(async () => {
    await client.close();
    await rm(root, { recursive: true, force: true });
  });
  let diagnostics = '';
  transport.stderr?.on('data', (value) => { diagnostics += value.toString(); });
  await client.connect(transport, { timeout: 5000 });
  assert.equal((await client.listTools()).tools.length, 13);
  assert.equal((await preview(client, { kind: 'setup' })).structuredContent.value.authorityIssued, false);
  assert.equal((await client.callTool({ name: 'missionspec_project_status', arguments: {} })).structuredContent.value.state, 'not-initialized');
  await client.close();
  assert.deepEqual(await readdir(root), []);
  assert(!diagnostics.includes('telemetry'));
});

test('optional context is explicitly absent without installing or invoking a provider', async (context) => {
  const f = await fixture(context);
  const inspected = await f.client.callTool({ name: 'missionspec_context', arguments: {} });
  assert.equal(inspected.structuredContent.value.state, 'absent');
  const request = await preview(f.client, { kind: 'context', query: 'Find the example.', paths: ['src/example.ts'], allowRemoteProcessing: true });
  assert.equal(request.structuredContent.value.review.state, 'not-ready');
  assert.equal(request.structuredContent.value.review.availability.state, 'absent');
  assert.equal(request.structuredContent.value.preview, null);
  assert.deepEqual(await readdir(f.root), []);
});
