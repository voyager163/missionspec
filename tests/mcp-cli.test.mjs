import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { runCli } from '../dist/cli/main.js';
import { observeWorkspaceRoot } from '../dist/api/index.js';

const executable = path.resolve('dist/cli/main.js');
async function fixture(t) {
  const root = path.resolve(`.mcp-cli-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('MCP startup never prints CLI JSON, help, version or rejected inputs onto protocol stdout', async () => {
  for (const argv of [
    ['mcp', '--json'], ['mcp', '--help'], ['mcp', '--version'], ['--json', 'mcp', '--help'],
    ['mcp', 'extra'], ['mcp', '--host', 'copilot'], ['mcp', '--yes', '--json'],
    ['--json', 'mcp', '--unknown', 'PRIVATE-REJECTED-MARKER'],
  ]) {
    let stdout = '';
    let stderr = '';
    const code = await runCli(argv, { stdout: (value) => { stdout += value; }, stderr: (value) => { stderr += value; } });
    assert.notEqual(code, 0);
    assert.equal(stdout, '');
    assert.match(stderr, /invalid-input/u);
    assert(!stderr.includes('PRIVATE-REJECTED-MARKER'));
  }
});

test('MCP CLI starts quietly and exits cleanly on input EOF without initializing the workspace', async (t) => {
  const root = await fixture(t);
  const result = spawnSync(process.execPath, [executable, 'mcp', '--no-telemetry'], {
    cwd: root, input: '', encoding: 'utf8', timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
  assert.deepEqual(await readdir(root), []);
});

test('real SDK stdio negotiation through the CLI uses the fixed CWD and never treats capabilities or environment as authority', async (t) => {
  const root = await fixture(t);
  const protocolErrors = [];
  const client = new Client({ name: 'TEST-clientInfo-not-approval', version: '1' }, { capabilities: { elicitation: { form: {} } } });
  client.onerror = (error) => { protocolErrors.push(error); };
  const transport = new StdioClientTransport({
    command: process.execPath, args: [executable, 'mcp'], cwd: root, stderr: 'pipe',
    env: { MISSIONSPEC_APPROVED: 'true', MISSIONSPEC_ROOT: path.dirname(root) },
  });
  let stderr = '';
  transport.stderr?.on('data', (chunk) => { stderr += chunk.toString(); });
  t.after(async () => client.close());
  await client.connect(transport);
  const version = JSON.parse(await readFile(path.resolve('package.json'), 'utf8')).version;
  assert.equal(client.getServerVersion().version, version);
  const tools = await client.listTools();
  assert(tools.tools.some((tool) => tool.name === 'missionspec_project_status'));
  assert(!tools.tools.some((tool) => tool.name === 'missionspec_apply'));
  const status = await client.callTool({ name: 'missionspec_project_status', arguments: {} });
  assert.equal(status.structuredContent.value.state, 'not-initialized');
  assert.equal(status.structuredContent.value.rootDigest, (await observeWorkspaceRoot(root)).rootDigest);
  const rejected = await client.callTool({ name: 'missionspec_project_status', arguments: {
    root: path.dirname(root), approved: true, clientInfo: { role: 'owner' },
  } });
  assert.equal(rejected.isError, true);
  assert.deepEqual(await readdir(root), []);
  await client.close();
  assert.deepEqual(protocolErrors, []);
  assert.equal(stderr, '');
});
