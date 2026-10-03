import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { METADATA_METHODS, metadataArguments, metadataLimits, probeMetadataConfinement, readConfinedMetadata } from './helpers/native-metadata-preflight.mjs';

test('prepared native metadata launchers have no prompt, session or Codex route', () => {
  assert.deepEqual(metadataArguments('claude', '/synthetic/logs'), ['auth', 'status', '--json']);
  assert.deepEqual(metadataArguments('copilot', '/synthetic/logs'), ['--headless', '--stdio', '--no-auto-update', '--log-level', 'none', '--log-dir', '/synthetic/logs']);
  for (const host of ['codex', 'other']) assert.throws(() => metadataArguments(host, '/synthetic/logs'));
  assert(Object.isFrozen(METADATA_METHODS));
  assert.deepEqual(METADATA_METHODS, ['connect', 'status.get', 'auth.getStatus', 'user.settings.get', 'models.list', 'account.getQuota']);
});

test('metadata limits cannot expand the prepared deadline or byte budget', () => {
  assert.deepEqual(metadataLimits(), { timeoutMs: 30_000, maxOutputBytes: 2_000_000 });
  assert.deepEqual(metadataLimits({ timeoutMs: 1500, maxOutputBytes: 1024 }), { timeoutMs: 1500, maxOutputBytes: 1024 });
  for (const limits of [{ timeoutMs: 30_001 }, { maxOutputBytes: 2_000_001 }, { timeoutMs: 0 }, { maxOutputBytes: Infinity }]) {
    assert.throws(() => metadataLimits(limits));
  }
});

test('macOS metadata profile confines filesystem data and separately proves offline network denial', { skip: process.platform !== 'darwin' }, async () => {
  const report = await probeMetadataConfinement();
  for (const key of ['insideRead', 'insideWrite', 'outsideReadDenied', 'symlinkReadDenied', 'outsideWriteDenied', 'networkPositiveControl', 'offlineNetworkDenied']) {
    assert.equal(report[key], true, key);
  }
  assert.equal(report.onlineMetadataNetworkConfined, false);
  assert.equal(report.remoteQuiescenceEstablished, false);
  assert.equal(report.modelCalls, 0);
  assert.equal(report.sessionsCreated, 0);
});

for (const mode of ['oversize', 'timeout', 'server-request']) {
  test(`prepared launcher fences synthetic ${mode} without fallback or quiescence claims`, { skip: process.platform !== 'darwin' }, async (t) => {
    const root = await mkdtemp(path.join(process.cwd(), '.metadata-fixture-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    const home = path.join(root, 'home'), bin = path.join(root, 'bin');
    await mkdir(path.join(home, '.claude'), { recursive: true });
    await mkdir(path.join(home, '.copilot'));
    await mkdir(bin);
    const executable = path.join(bin, 'fixture.mjs');
    await writeFile(executable, `#!${process.execPath}
const mode=${JSON.stringify(mode)};
if(process.argv.includes('--version')) process.stdout.write('2.1.267 (Claude Code)\\n');
else if(mode==='oversize') process.stdout.write('x'.repeat(4096));
else if(mode==='timeout') setInterval(()=>{},1000);
else {
 const body=JSON.stringify({jsonrpc:'2.0',id:'native-tool',method:'session.create',params:{private:'NOT-RETAINED'}});
 process.stdout.write('Content-Length: '+Buffer.byteLength(body)+'\\r\\n\\r\\n'+body);
 setInterval(()=>{},1000);
}
`, { mode: 0o700 });
    const before = (await readdir(process.cwd())).filter(name => name.startsWith('.native-metadata-qualification-')).sort();
    const report = await readConfinedMetadata(mode === 'server-request' ? 'copilot' : 'claude', {
      executable, homeDirectory: home, limits: { timeoutMs: 1500, maxOutputBytes: 1024 },
    });
    assert.equal(report.status, 'blocked', JSON.stringify(report));
    assert.equal(report.modelCalls, 0);
    assert.equal(report.sessionsCreated, 0);
    assert.equal(report.timeoutProvesRemoteQuiescence, false);
    assert.match(report.reason, mode === 'oversize' ? /byte limit/ : mode === 'timeout' ? /deadline/ : /protocol/);
    assert(!JSON.stringify(report).includes('NOT-RETAINED'));
    assert.deepEqual((await readdir(process.cwd())).filter(name => name.startsWith('.native-metadata-qualification-')).sort(), before);
  });
}
