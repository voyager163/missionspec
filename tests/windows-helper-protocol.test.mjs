import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { controlHelper } from './fixtures/windows-controlled-helper.mjs';

function fixture(t, source) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: ['pipe', 'pipe', 'pipe'] });
  const controller = controlHelper(child, { operation: { kind: 'test-only' } }, 3000);
  t.after(controller.stop);
  return controller;
}

test('helper terminal failures with a phase never become acknowledgable checkpoints', async (t) => {
  const c = fixture(t, `
    process.stdin.once('data', () => {
      process.stdin.destroy();
      process.stdout.write(JSON.stringify({ok:false,reason:'effect-rename',phase:'file-operation',line:251})+'\\n');
      process.exitCode=1;
    });
  `);
  await assert.rejects(c.checkpoint('preimage-renamed'), /native: effect-rename.*phase=file-operation/u);
  await assert.rejects(c.ack(), /terminal responses cannot be acknowledged.*effect-rename/u);
});

test('closed input preserves the later native failure instead of an unhandled EPIPE', async (t) => {
  const c = fixture(t, `
    process.stdin.once('data', () => {
      process.stdin.once('close', () => {
        process.stdout.write('{"phase":"publication-held"}\\n');
        setTimeout(() => {
          process.stdout.write('{"ok":false,"reason":"effect-rename","phase":"file-operation"}\\n');
          process.exitCode=1;
        }, 100);
      });
      process.stdin.destroy();
    });
  `);
  await c.checkpoint('publication-held');
  await assert.rejects(async () => {
    // Some pipe implementations accept the final buffered write before reporting
    // closure. Either boundary must retain the native failure, never report success.
    await c.ack();
    await c.checkpoint('preimage-renamed');
  }, /native: effect-rename/u);
});

test('helper success before a required checkpoint is not accepted', async (t) => {
  const c = fixture(t, `
    process.stdin.once('data', () => {
      process.stdin.destroy();
      process.stdout.write('{"ok":true,"value":null}\\n');
    });
  `);
  await assert.rejects(c.checkpoint('created-held'), /expected checkpoint created-held.*unexpected native success/u);
});

test('helper checkpoints must match the exact expected order', async (t) => {
  const c = fixture(t, `
    process.stdin.once('data', () => { process.stdout.write('{"phase":"file-written"}\\n'); });
  `);
  await assert.rejects(c.checkpoint('created-held'), /unexpected checkpoint; expected created-held/u);
});

test('helper completion requires every asserted checkpoint and an explicit successful terminal result', async (t) => {
  const c = fixture(t, `
    import {createInterface} from 'node:readline';
    let count=0;
    const lines=createInterface({input:process.stdin});
    lines.on('line', line => {
      if(count++===0) {process.stdout.write('{"phase":"created-held"}\\n');return;}
      if(line!=='continue') throw new Error('invalid continuation');
      if(count===2) process.stdout.write('{"phase":"file-written"}\\n');
      else { process.stdout.write('{"ok":true,"value":{"acknowledgements":2}}\\n'); process.stdin.destroy(); }
    });
  `);
  await c.checkpoint('created-held');
  assert.deepEqual(await c.finish(0, ['file-written']), { ok: true, value: { acknowledgements: 2 } });
});

test('expected helper failure requires the exact native reason, not merely a nonzero exit', async (t) => {
  const c = fixture(t, `
    import {createInterface} from 'node:readline';
    let count=0;
    createInterface({input:process.stdin}).on('line', line => {
      if(count++===0) process.stdout.write('{"phase":"delete-held"}\\n');
      else { process.stdout.write('{"ok":false,"reason":"effect-open","phase":"file-operation"}\\n'); process.stdin.destroy(); process.exitCode=1; }
    });
  `);
  await c.checkpoint('delete-held');
  await assert.rejects(c.finish(1, [], 'effect-preimage'), /unexpected native failure.*effect-open/u);
});
