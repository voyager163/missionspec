import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { lstatSync, rmdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import {
  validateWindowsStatePath, windowsPrivateEntries, WindowsPrivateStateError,
} from '../../dist/adapters/platform/windows-private-state.js';

export const windows = { skip: process.platform !== 'win32', timeout: 240_000 };
export const privateEntry = (target, directory = false, create = false) =>
  windowsPrivateEntries([{ path: target, directory, writable: true, create }]);

export function powershell(source, value) {
  const script = "[Console]::InputEncoding = [Text.UTF8Encoding]::new($false, $true)\n" +
    "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false, $true)\n" +
    "Import-Module -Name 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1' -ErrorAction Stop\n" + source;
  const result = spawnSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
  ], { input: JSON.stringify(value), encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536, windowsHide: true, shell: false });
  assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
  return JSON.parse(result.stdout);
}

let knownUserFolders;
function fixtureEntry(target) {
  try { return lstatSync(target, { bigint: true }); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

export function safeFixtureFailure(error) {
  if (error instanceof WindowsPrivateStateError) return error.message;
  return ['EPERM', 'EACCES', 'ENOENT', 'EEXIST', 'ENOTDIR', 'ENOTEMPTY', 'EIO', 'EBUSY'].includes(error?.code)
    ? `filesystem-${error.code}` : 'fixture-operation-unavailable';
}

export function removeFixtureRoot(root, identity, emptyOnly = false) {
  const current = fixtureEntry(root);
  if (current === null) return;
  if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== identity.dev || current.ino !== identity.ino) {
    throw new Error('Fixture root identity changed; cleanup refused');
  }
  privateEntry(root, true);
  const verified = fixtureEntry(root);
  if (verified === null || verified.dev !== identity.dev || verified.ino !== identity.ino) {
    throw new Error('Fixture root changed during cleanup validation');
  }
  if (emptyOnly) rmdirSync(root);
  else rmSync(root, { recursive: true });
}

export function createPrivateFixtureRoot() {
  knownUserFolders ??= powershell(String.raw`
$ErrorActionPreference = 'Stop'
[Console]::Out.Write((@{
  profile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
  localAppData=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
} | ConvertTo-Json -Compress))
`, null);
  const { profile, localAppData } = knownUserFolders;
  validateWindowsStatePath(profile);
  validateWindowsStatePath(localAppData);
  const relative = path.relative(profile, localAppData);
  assert.ok(relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative), 'Local application data must lie inside the current OS-reported user profile');
  const failures = [];
  for (const [kind, candidate] of [['local-app-data', localAppData], ['profile', profile]]) {
    const root = path.join(candidate, `.windows-state-${randomUUID()}`);
    let before;
    try { before = fixtureEntry(root); } catch (error) {
      failures.push(`${kind}: no creation attempted because the exclusive path could not be inspected: ${safeFixtureFailure(error)}`);
      continue;
    }
    if (before !== null) throw new Error('Exclusive fixture UUID path already exists; no cleanup attempted');
    try {
      // Existing containers use ancestor policy; only the new child is private.
      privateEntry(root, true, true);
    } catch (error) {
      const reason = safeFixtureFailure(error);
      let partial;
      try { partial = fixtureEntry(root); } catch (inspectionError) {
        throw new Error(`${kind}: ${reason}; creation state cannot be inspected: ${safeFixtureFailure(inspectionError)}`);
      }
      if (partial !== null) {
        try { removeFixtureRoot(root, partial, true); } catch (cleanupError) {
          throw new Error(`${kind}: ${reason}; partial creation retained because safe empty-root cleanup failed: ${safeFixtureFailure(cleanupError)}`);
        }
        throw new Error(`${kind}: ${reason}; partial creation occurred and its verified empty UUID root was removed; no fallback attempted`);
      }
      failures.push(`${kind}: ${reason}`);
      continue;
    }
    let identity;
    try { identity = fixtureEntry(root); } catch (error) {
      throw new Error(`${kind}: successful creation could not be identity-checked; qualification stopped: ${safeFixtureFailure(error)}`);
    }
    if (identity === null) throw new Error(`${kind}: successfully created fixture disappeared; qualification stopped`);
    if (!identity.isDirectory() || identity.isSymbolicLink()) {
      throw new Error(`${kind}: successfully created fixture changed type; qualification stopped without cleanup`);
    }
    return { root, identity, kind };
  }
  throw new Error(`No private NTFS fixture root could be created under the OS-reported profile containers. ${failures.join(' | ')}`);
}
