import { spawnSync } from 'node:child_process';
import { lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const systemRoot = 'C:\\Windows';
const systemPowerShell = `${systemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const helper = fileURLToPath(new URL('../../../assets/platform/windows-private-state.ps1', import.meta.url));
const accessPolicy = fileURLToPath(new URL('../../../assets/platform/windows-access-policy.ps1', import.meta.url));

export class WindowsPrivateStateError extends Error {
  readonly code = 'EPERM';
  constructor(reason = 'unavailable') {
    super(`Windows private state requires a canonical current-user-owned local NTFS path and restrictive inheritable SID ACLs (${reason}).`);
  }
}

const diagnosticPhases = [
  'input', 'native-bindings', 'entry', 'creation', 'volume', 'entry-open', 'entry-information', 'entry-attributes',
  'entry-final-path', 'entry-acl-read', 'entry-acl-parse', 'entry-owner', 'entry-aces', 'entry-user-access',
  'entry-inheritance', 'json-module', 'json-input', 'access-policy',
  'directory-identity', 'directory-flush', 'directory-close', 'flush-options',
];
const exceptionTypes = [
  'none', 'other', 'RuntimeException', 'MethodException', 'MethodInvocationException', 'PSInvalidCastException',
  'ParameterBindingException', 'ArgumentException', 'ArgumentNullException', 'InvalidOperationException',
  'NotSupportedException', 'TypeLoadException', 'MissingMethodException', 'IOException', 'UnauthorizedAccessException',
  'FileNotFoundException', 'DirectoryNotFoundException', 'CmdletInvocationException', 'ActionPreferenceStopException',
];

export function windowsFailureDiagnostic(output: unknown): string {
  if (typeof output !== 'object' || output === null) return 'unavailable';
  const allowedReason = [
    ...diagnosticPhases, 'system-executable', 'open', 'identity', 'type', 'links', 'alias', 'acl', 'owner',
    'unsupported-ace', 'public-access', 'user-access', 'inheritance', 'close', 'descriptor', 'create',
  ];
  const reason: unknown = Reflect.get(output, 'reason');
  if (typeof reason !== 'string' || !allowedReason.includes(reason)) return 'unavailable';
  const parts = [reason];
  for (const [field, values] of [
    ['phase', diagnosticPhases], ['boundary', ['helper', 'system', 'ancestor', 'private']],
    ['exceptionType', exceptionTypes], ['innerType', exceptionTypes],
  ] as const) {
    const value: unknown = Reflect.get(output, field);
    if (typeof value === 'string' && values.some((allowed) => allowed === value)) parts.push(`${field}=${value}`);
  }
  const line: unknown = Reflect.get(output, 'line');
  if (typeof line === 'number' && Number.isSafeInteger(line) && line > 0 && line <= 10_000) parts.push(`line=${line}`);
  return parts.join('; ');
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
    for (const filename of [helper, accessPolicy]) {
      const resource = lstatSync(filename);
      if (!resource.isFile() || resource.isSymbolicLink()) {
        throw new WindowsPrivateStateError('helper-resource');
      }
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
  readonly flushIdentity?: { readonly device: string; readonly inode: string };
}

export class WindowsDirectoryDurabilityError extends Error {
  readonly code = 'EIO';
  readonly durability = 'unconfirmed';
  constructor(detail = 'unavailable') { super(`Windows directory durability was not confirmed: ${detail}`); }
}

/** Trusted composition only; expected identity is a guard, never ownership or authority proof. */
export function syncWindowsPrivateDirectory(directory: string, expected: { readonly dev: bigint; readonly ino: bigint }): void {
  try {
    if (typeof expected !== 'object' || expected === null ||
        typeof expected.dev !== 'bigint' || expected.dev < 0n || expected.dev > 0xffff_ffffn ||
        typeof expected.ino !== 'bigint' || expected.ino <= 0n || expected.ino > 0xffff_ffff_ffff_ffffn) {
      throw new WindowsDirectoryDurabilityError('invalid directory identity');
    }
    windowsPrivateEntries([{
      path: directory, directory: true, writable: true,
      flushIdentity: { device: expected.dev.toString(), inode: expected.ino.toString() },
    }]);
  } catch (error) {
    if (error instanceof WindowsDirectoryDurabilityError) throw error;
    throw new WindowsDirectoryDurabilityError(error instanceof WindowsPrivateStateError ? error.message : 'helper unavailable');
  }
}

/** Private-entry checks and the separately requested, identity-guarded directory barrier; never authority. */
export function windowsPrivateEntries(entries: readonly WindowsPrivateEntry[]): void {
  requireWindowsPrivateState();
  if (entries.length === 0 || entries.length > 8) throw new WindowsPrivateStateError();
  for (const entry of entries) {
    validateWindowsStatePath(entry.path);
    if (entry.flushIdentity !== undefined && (entry.directory !== true || entry.writable !== true || entry.create === true ||
        typeof entry.flushIdentity.device !== 'string' || !/^(?:0|[1-9][0-9]{0,9})$/u.test(entry.flushIdentity.device) ||
        BigInt(entry.flushIdentity.device) > 0xffff_ffffn ||
        typeof entry.flushIdentity.inode !== 'string' || !/^[1-9][0-9]{0,19}$/u.test(entry.flushIdentity.inode) ||
        BigInt(entry.flushIdentity.inode) > 0xffff_ffff_ffff_ffffn)) {
      throw new WindowsPrivateStateError('flush-options');
    }
  }
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
      throw new WindowsPrivateStateError(windowsFailureDiagnostic(output));
    } catch (error) { if (error instanceof WindowsPrivateStateError) throw error; }
    throw new WindowsPrivateStateError();
  }
}
