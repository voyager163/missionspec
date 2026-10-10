import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { fileURLToPath } from 'node:url';
import { windowsFailureDiagnostic } from '../../dist/adapters/platform/windows-private-state.js';

const helper = fileURLToPath(new URL('../../assets/platform/windows-private-state.ps1', import.meta.url));
const powerShell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const spawnSync = childProcess.spawnSync;
let reports = 0;

childProcess.spawnSync = function (...args) {
  const result = spawnSync.apply(this, args);
  // Observe genuine helper failures without changing arguments, execution,
  // return values, or any native ownership/console decision.
  if (args[0] === powerShell && args[1]?.includes(helper) && result.status !== 0 && reports < 4) {
    let native = 'unavailable';
    try {
      if (typeof result.stdout === 'string' && result.stdout.length <= 16_384) {
        native = windowsFailureDiagnostic(JSON.parse(result.stdout.trim().split(/\r?\n/u).at(-1)));
      }
    } catch { /* Never emit a raw native error or helper output. */ }
    reports += 1;
    process.stderr.write(`CLI_NATIVE_FAILURE:${JSON.stringify({ native })}\n`);
  }
  return result;
};
syncBuiltinESMExports();
