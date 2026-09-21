import { spawnSync } from 'node:child_process';
import { lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const systemRoot = 'C:\\Windows';
const systemPowerShell = `${systemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const helper = fileURLToPath(new URL('../../../assets/platform/windows-private-state.ps1', import.meta.url));

export class WindowsPrivateStateError extends Error {
  readonly code = 'EPERM';
  constructor(reason = 'unavailable') {
    super(`Windows private state requires a canonical current-user-owned local NTFS path and restrictive inheritable SID ACLs (${reason}).`);
  }
}

export function requireWindowsPrivateState(): void {
  // An edited process.platform on a POSIX host is not a Windows qualification.
  if (process.platform !== 'win32' || path.sep !== '\\' || process.getuid !== undefined) {
    throw new WindowsPrivateStateError();
  }
}

function validateSystemPowerShell(): void {
  // The environment may restrict this fixed installation, never select an executable.
  if (process.env.SystemRoot?.toLowerCase() !== systemRoot.toLowerCase()) {
    throw new WindowsPrivateStateError('system-executable');
  }
  try {
    let current = path.parse(systemPowerShell).root;
    for (const component of systemPowerShell.slice(current.length).split(path.sep)) {
      current = path.join(current, component);
      const entry = lstatSync(current);
      if (entry.isSymbolicLink() || (current === systemPowerShell ? !entry.isFile() : !entry.isDirectory()) ||
          realpathSync.native(current).toLowerCase() !== current.toLowerCase()) {
        throw new WindowsPrivateStateError('system-executable');
      }
    }
    const resource = lstatSync(helper);
    if (!resource.isFile() || resource.isSymbolicLink()) {
      throw new WindowsPrivateStateError('helper-resource');
    }
  } catch (error) {
    if (error instanceof WindowsPrivateStateError) throw error;
    throw new WindowsPrivateStateError('system-executable');
  }
}

export function validateWindowsStatePath(value: string): void {
  if (typeof value !== 'string' || value.length > 240 || !/^[A-Z]:\\/u.test(value) ||
      path.win32.normalize(value) !== value || value.endsWith('\\') ||
      value.slice(3).split('\\').some((part) => part.length === 0 || /[\u0000-\u001f\u007f<>:"/|?*]/u.test(part) ||
        /[. ]$/u.test(part) || /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/iu.test(part))) {
    throw new WindowsPrivateStateError();
  }
}

export interface WindowsPrivateEntry {
  readonly path: string;
  readonly directory: boolean;
  readonly writable: boolean;
  readonly create?: boolean;
}

/** Privacy only: no directory-durability or authority capability is supplied here. */
export function windowsPrivateEntries(entries: readonly WindowsPrivateEntry[]): void {
  requireWindowsPrivateState();
  if (entries.length === 0 || entries.length > 8) throw new WindowsPrivateStateError();
  for (const entry of entries) validateWindowsStatePath(entry.path);
  validateSystemPowerShell();
  const result = spawnSync(systemPowerShell, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-File', helper,
  ], {
    input: JSON.stringify({ entries }), encoding: 'utf8', windowsHide: true,
    timeout: 20_000, maxBuffer: 16_384, shell: false,
  });
  if (result.error !== undefined || result.status !== 0 || result.stdout !== '{"ok":true}') {
    try {
      const output: unknown = JSON.parse(result.stdout);
      const reason: unknown = typeof output === 'object' && output !== null ? Reflect.get(output, 'reason') : undefined;
      if (typeof reason === 'string' && [
        'input', 'native-bindings', 'entry', 'creation', 'system-executable', 'open', 'identity', 'type', 'links', 'alias', 'acl', 'owner',
        'unsupported-ace', 'public-access', 'user-access', 'inheritance', 'close', 'volume', 'descriptor', 'create',
      ].includes(reason)) throw new WindowsPrivateStateError(reason);
    } catch (error) { if (error instanceof WindowsPrivateStateError) throw error; }
    throw new WindowsPrivateStateError();
  }
}
