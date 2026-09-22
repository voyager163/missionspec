import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { executeWindowsCheck } from '../../dist/adapters/platform/windows-execution.js';

const program = realpathSync.native(process.execPath);
await executeWindowsCheck({
  program, programDigest: `sha256:${createHash('sha256').update(readFileSync(program)).digest('hex')}`,
  cwd: process.argv[2], timeoutMs: 60_000,
  argv: ['-e', `
    const fs = require('node:fs');
    const child = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 100)'], { stdio: 'ignore', detached: true });
    fs.writeFileSync('owned-pids.json', JSON.stringify([process.pid, child.pid]));
    setInterval(() => {}, 100);
  `],
});
