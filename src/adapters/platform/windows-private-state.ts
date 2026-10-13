import { spawnSync } from 'node:child_process';
import { lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const systemRoot = 'C:\\Windows';
const systemPowerShell = `${systemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const helper = fileURLToPath(new URL('../../../assets/platform/windows-private-state.ps1', import.meta.url));
const accessPolicy = fileURLToPath(new URL('../../../assets/platform/windows-access-policy.ps1', import.meta.url));
const fileOperations = fileURLToPath(new URL('../../../assets/platform/windows-file-operations.ps1', import.meta.url));
const privateStateRequirement = 'Windows private state requires a canonical current-user-owned local NTFS path and restrictive inheritable SID ACLs';
const privateStateDiagnostics = new WeakMap<WindowsPrivateStateError, string>();

export class WindowsPrivateStateError extends Error {
  readonly code = 'EPERM';
  constructor(reason: unknown = 'unavailable') {
    const diagnostic = windowsFailureDiagnostic(typeof reason === 'string' ? { reason } : reason);
    super(`${privateStateRequirement} (${diagnostic}).`);
    privateStateDiagnostics.set(this, diagnostic);
  }
}

const diagnosticPhases = [
  'input', 'native-bindings', 'entry', 'creation', 'volume', 'entry-open', 'entry-information', 'entry-attributes',
  'entry-final-path', 'entry-acl-read', 'entry-acl-parse', 'entry-owner', 'entry-aces', 'entry-user-access',
  'entry-inheritance', 'json-module', 'json-input', 'access-policy',
  'directory-identity', 'directory-flush', 'directory-close', 'flush-options',
  'file-metadata', 'file-security', 'process-inspection', 'process-present', 'process-instance',
  'file-security-owner', 'file-security-group', 'file-security-control', 'file-security-dacl',
  'file-security-descriptor', 'file-security-policy',
  'file-security-copy', 'file-security-set',
  'writer-lease', 'lease-close',
  'file-operation', 'effect-root', 'effect-path', 'effect-open', 'effect-read', 'effect-write', 'effect-size',
  'effect-identity', 'effect-preimage', 'effect-flush', 'effect-rename', 'effect-delete', 'effect-cancelled',
  'effect-operation', 'handle-close', 'publication-intent', 'publication-state',
  'sqlite-read-lock', 'sqlite-read-busy', 'sqlite-header',
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
    'helper-resource', 'path-length', 'path-format', 'unavailable',
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
  const nativeStatus: unknown = Reflect.get(output, 'nativeStatus');
  if (typeof nativeStatus === 'number' && Number.isInteger(nativeStatus) &&
      nativeStatus >= -2147483648 && nativeStatus <= 2147483647) parts.push(`nativeStatus=${nativeStatus}`);
  return parts.join('; ');
}

/** Preserve only the constructor's sanitized diagnostic, never a mutable Error.message. */
export function windowsPrivateStateDiagnostic(error: WindowsPrivateStateError): string {
  return privateStateDiagnostics.get(error) ?? 'unavailable';
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
    for (const filename of [helper, accessPolicy, fileOperations]) {
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
  if (typeof value === 'string' && value.length > 240) throw new WindowsPrivateStateError('path-length');
  if (typeof value !== 'string' || !/^[A-Z]:\\/u.test(value) ||
      path.win32.normalize(value) !== value || value.endsWith('\\') ||
      value.slice(3).split('\\').some((part) => part.length === 0 || /[\u0000-\u001f\u007f<>:"/|?*]/u.test(part) ||
        /[. ]$/u.test(part) || /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/iu.test(part))) {
    throw new WindowsPrivateStateError('path-format');
  }
}

export interface WindowsPrivateEntry {
  readonly path: string;
  readonly directory: boolean;
  readonly writable: boolean;
  readonly create?: boolean;
  readonly flushIdentity?: { readonly device: string; readonly inode: string };
  readonly ordinaryFile?: boolean;
  readonly copySecurityFrom?: string;
  readonly sameSecurityAs?: string;
}

export interface WindowsWriterLease {
  readonly path: string;
  readonly dev: bigint;
  readonly ino: bigint;
  readonly digest: string;
  readonly process?: WindowsProcessInstance;
}

export interface WindowsProcessInstance {
  readonly schemaVersion: 1;
  readonly pid: number;
  readonly creationFileTime: string;
}

function closedRecord(value: unknown, keys: readonly string[], reason: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
      Reflect.ownKeys(value).length !== keys.length || keys.some((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field === undefined || !('value' in field);
      })) throw new WindowsPrivateStateError(reason);
  return value as Record<string, unknown>;
}

export function parseWindowsProcessInstance(value: unknown): WindowsProcessInstance {
  const instance = closedRecord(value, ['schemaVersion', 'pid', 'creationFileTime'], 'process-instance');
  if (instance.schemaVersion !== 1 || typeof instance.pid !== 'number' || !Number.isSafeInteger(instance.pid) ||
      instance.pid < 1 || instance.pid > 2147483647 ||
      typeof instance.creationFileTime !== 'string' || !/^[1-9][0-9]{0,18}$/u.test(instance.creationFileTime) ||
      BigInt(instance.creationFileTime) < 116_444_736_000_000_000n ||
      BigInt(instance.creationFileTime) > 0x7fff_ffff_ffff_ffffn) throw new WindowsPrivateStateError('process-instance');
  return Object.freeze({ schemaVersion: 1, pid: instance.pid, creationFileTime: instance.creationFileTime });
}

let currentProcessInstance: WindowsProcessInstance | undefined;

/** Module-local only: a running Node process cannot survive its own Windows PID reuse. */
export function currentWindowsProcessInstance(): WindowsProcessInstance {
  requireWindowsPrivateState();
  if (currentProcessInstance?.pid !== process.pid) {
    const instance = parseWindowsProcessInstance(invokeWindowsHelper({ kind: 'process-instance', pid: process.pid }));
    if (instance.pid !== process.pid) throw new WindowsPrivateStateError('process-instance');
    currentProcessInstance = instance;
  }
  return currentProcessInstance;
}

/** Closed legacy/new lock decoding; no stored record is upgraded or repaired. */
export function parseWindowsWriterLock(value: unknown): {
  readonly kind: 'transaction' | 'runtime' | 'evidence-prune' | 'state-lifecycle';
  readonly id?: string;
  readonly pid: number;
  readonly process?: WindowsProcessInstance;
} {
  if (typeof value !== 'object' || value === null) throw new WindowsPrivateStateError('writer-lease');
  const fields = Object.getOwnPropertyDescriptors(value);
  const kind = fields.transactionId !== undefined ? 'transaction' : fields.kind?.value;
  const version = fields.schemaVersion?.value;
  const modern = version === 2;
  const keys = kind === 'transaction' ? ['transactionId', 'pid'] :
    kind === 'runtime' ? ['kind', 'pid'] :
      kind === 'evidence-prune' || kind === 'state-lifecycle' ? ['schemaVersion', 'kind', 'id', 'pid', 'nonce'] : undefined;
  if (keys === undefined) throw new WindowsPrivateStateError('writer-lease');
  const owner = closedRecord(value, modern ? [...new Set([...keys, 'schemaVersion', 'nonce', 'process'])] : keys, 'writer-lease');
  if ((!modern && kind !== 'transaction' && kind !== 'runtime' && version !== 1) ||
      typeof owner.pid !== 'number' || !Number.isSafeInteger(owner.pid) || owner.pid < 1 || owner.pid > 2147483647 ||
      kind === 'transaction' && (typeof owner.transactionId !== 'string' || !/^[a-f0-9-]{36}$/u.test(owner.transactionId)) ||
      (kind === 'evidence-prune' || kind === 'state-lifecycle') &&
        (typeof owner.id !== 'string' || !/^sha256:[a-f0-9]{64}$/u.test(owner.id) ||
          typeof owner.nonce !== 'string' || owner.nonce.length === 0 || owner.nonce.length > 80) ||
      modern && (typeof owner.nonce !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(owner.nonce))) {
    throw new WindowsPrivateStateError('writer-lease');
  }
  const instance = modern ? parseWindowsProcessInstance(owner.process) : undefined;
  if (instance !== undefined && instance.pid !== owner.pid) throw new WindowsPrivateStateError('writer-lease');
  return Object.freeze({
    kind, pid: owner.pid, ...(kind === 'runtime' ? {} : { id: String(kind === 'transaction' ? owner.transactionId : owner.id) }),
    ...(instance === undefined ? {} : { process: instance }),
  });
}

export interface WindowsFileReference {
  readonly device: string;
  readonly inode: string;
  readonly digest: string;
  readonly security: string;
}

export interface WindowsFileScope {
  readonly root: string;
  readonly dev: bigint;
  readonly ino: bigint;
  readonly lease?: WindowsWriterLease;
}

function operationScope(scope: WindowsFileScope): object {
  requireWindowsPrivateState();
  validateWindowsStatePath(scope.root);
  if (typeof scope.dev !== 'bigint' || scope.dev < 0n || scope.dev > 0xffff_ffffn ||
      typeof scope.ino !== 'bigint' || scope.ino <= 0n || scope.ino > 0xffff_ffff_ffff_ffffn) {
    throw new WindowsPrivateStateError('effect-root');
  }
  return {
    root: scope.root, rootIdentity: { device: String(scope.dev), inode: String(scope.ino) },
    ...(scope.lease === undefined ? {} : { lease: {
      path: scope.lease.path, device: String(scope.lease.dev), inode: String(scope.lease.ino), digest: scope.lease.digest,
      ...(scope.lease.process === undefined ? {} : { process: parseWindowsProcessInstance(scope.lease.process) }),
    } }),
  };
}

function operationPath(scope: WindowsFileScope, filename: string): string {
  validateWindowsStatePath(filename);
  if (!filename.startsWith(`${scope.root}${path.sep}`)) throw new WindowsPrivateStateError('effect-path');
  return filename;
}

function operationDigest(value: string): string {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) throw new WindowsPrivateStateError('effect-preimage');
  return value;
}

function fileReference(value: unknown): WindowsFileReference {
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
      Object.keys(value).length !== 4) throw new WindowsPrivateStateError('effect-identity');
  const device: unknown = Reflect.get(value, 'device');
  const inode: unknown = Reflect.get(value, 'inode');
  const digest: unknown = Reflect.get(value, 'digest');
  const security: unknown = Reflect.get(value, 'security');
  if (typeof device !== 'string' || !/^(?:0|[1-9][0-9]{0,9})$/u.test(device) || BigInt(device) > 0xffff_ffffn ||
      typeof inode !== 'string' || !/^[1-9][0-9]{0,19}$/u.test(inode) || BigInt(inode) > 0xffff_ffff_ffff_ffffn ||
      typeof digest !== 'string' || typeof security !== 'string') throw new WindowsPrivateStateError('effect-identity');
  return { device, inode, digest: operationDigest(digest), security: operationDigest(security) };
}

/** Allocates, writes and flushes one CREATE_NEW object without a pathname reopen. */
export function writeWindowsPrivateFile(scope: WindowsFileScope, filename: string, content: string, copySecurityFrom?: string): WindowsFileReference {
  if (typeof content !== 'string' || Buffer.byteLength(content) > 6_000_000) throw new WindowsPrivateStateError('effect-size');
  const destination = operationPath(scope, filename);
  if (copySecurityFrom !== undefined && path.dirname(copySecurityFrom) !== path.dirname(destination)) throw new WindowsPrivateStateError('effect-path');
  return fileReference(invokeWindowsHelper({ operation: {
    ...operationScope(scope), kind: 'create', path: destination, content,
    ...(copySecurityFrom === undefined ? {} : { copySecurityFrom: operationPath(scope, copySecurityFrom) }),
  } }));
}

export function ensureWindowsPrivateDirectories(scope: WindowsFileScope, directory: string): void {
  invokeWindowsHelper({ operation: { ...operationScope(scope), kind: 'parents', path: operationPath(scope, directory) } });
}

export function inspectWindowsPrivateFile(scope: WindowsFileScope, filename: string): WindowsFileReference {
  return fileReference(invokeWindowsHelper({ operation: {
    ...operationScope(scope), kind: 'inspect', path: operationPath(scope, filename),
  } }));
}

/** ACL/type/identity admission and bounded bytes are obtained from the same native held object. */
export function readWindowsPrivateFile(filename: string, expected: { readonly dev: bigint; readonly ino: bigint },
  maxBytes: number, prefix = false, privateRoot?: string): Buffer {
  return readWindowsHeldFile('read', filename, expected, maxBytes, prefix, privateRoot);
}

export interface WindowsSqliteStoreAdmission {
  readonly directoryIdentity: { readonly dev: bigint; readonly ino: bigint };
  readonly writable: boolean;
}

/** A fixed 100-byte header under SQLite's shared byte-range lock; not an immutable JSON reader. */
export function readWindowsSqliteHeader(filename: string, expected: { readonly dev: bigint; readonly ino: bigint },
  store?: WindowsSqliteStoreAdmission): Buffer {
  if (path.basename(filename) !== 'ledger.sqlite' || path.basename(path.dirname(filename)) !== 'state' ||
      path.basename(path.dirname(path.dirname(filename))) !== '.missionspec') throw new WindowsPrivateStateError('sqlite-header');
  return readWindowsHeldFile('sqlite-header', filename, expected, 100, true,
    store === undefined ? undefined : path.dirname(path.dirname(filename)), store);
}

function readWindowsHeldFile(kind: 'read' | 'sqlite-header', filename: string,
  expected: { readonly dev: bigint; readonly ino: bigint }, maxBytes: number, prefix: boolean,
  privateRoot = path.dirname(filename), store?: WindowsSqliteStoreAdmission): Buffer {
  requireWindowsPrivateState();
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 8_000_000) throw new WindowsPrivateStateError('effect-size');
  if (store !== undefined && (kind !== 'sqlite-header' || typeof store.writable !== 'boolean')) {
    throw new WindowsPrivateStateError('sqlite-header');
  }
  for (const identity of [expected, ...(store === undefined ? [] : [store.directoryIdentity])]) {
    if (typeof identity.dev !== 'bigint' || identity.dev < 0n || identity.dev > 0xffff_ffffn ||
        typeof identity.ino !== 'bigint' || identity.ino <= 0n || identity.ino > 0xffff_ffff_ffff_ffffn) {
      throw new WindowsPrivateStateError('effect-identity');
    }
  }
  const parent = lstatSync(privateRoot, { bigint: true });
  const scope = { root: privateRoot, dev: parent.dev, ino: parent.ino };
  const value = closedRecord(invokeWindowsHelper({ operation: {
    ...operationScope(scope), kind, path: operationPath(scope, filename),
    expected: { device: String(expected.dev), inode: String(expected.ino) }, maxBytes, prefix,
    ...(store === undefined ? {} : { store: {
      directoryIdentity: { device: String(store.directoryIdentity.dev), inode: String(store.directoryIdentity.ino) },
      writable: store.writable,
    } }),
  } }, Math.ceil(maxBytes / 3) * 4 + 16_384), ['device', 'inode', 'contentBase64'], 'effect-read');
  if (value.device !== String(expected.dev) || value.inode !== String(expected.ino) ||
      typeof value.contentBase64 !== 'string' ||
      value.contentBase64.length > Math.ceil(maxBytes / 3) * 4 || /[^A-Za-z0-9+/=]/u.test(value.contentBase64)) {
    throw new WindowsPrivateStateError('effect-read');
  }
  const bytes = Buffer.from(value.contentBase64, 'base64');
  if (bytes.length > maxBytes || (kind === 'sqlite-header' && bytes.length !== 100) ||
      bytes.toString('base64') !== value.contentBase64) throw new WindowsPrivateStateError('effect-size');
  return bytes;
}

export function syncWindowsPrivateFile(scope: WindowsFileScope, filename: string, digest: string): void {
  invokeWindowsHelper({ operation: {
    ...operationScope(scope), kind: 'sync', path: operationPath(scope, filename), digest: operationDigest(digest),
  } });
}

/** Deletes only the held, verified object, never a later pathname occupant. */
export function removeWindowsPrivateFile(scope: WindowsFileScope, filename: string, digest: string,
  reference?: WindowsFileReference, absentProcess?: number | WindowsProcessInstance): void {
  if (typeof absentProcess === 'number' && (!Number.isSafeInteger(absentProcess) || absentProcess < 1 || absentProcess > 2147483647)) {
    throw new WindowsPrivateStateError('process-inspection');
  }
  invokeWindowsHelper({ operation: {
    ...operationScope(scope), kind: 'delete', path: operationPath(scope, filename), digest: operationDigest(digest),
    ...(reference === undefined ? {} : { reference: fileReference(reference) }),
    ...(absentProcess === undefined ? {} : typeof absentProcess === 'number' ? { absentProcess } :
      { absentInstance: parseWindowsProcessInstance(absentProcess) }),
  } });
}

export interface WindowsPublication {
  readonly relative: string;
  readonly transactionId: string;
  readonly index: number;
  readonly plan: string;
  readonly expected: string | 'absent';
  readonly proposed: string;
  readonly stageIdentity?: { readonly dev: bigint; readonly ino: bigint };
}

export function windowsPublication(scope: WindowsFileScope, publication: WindowsPublication, inspect = false):
  'absent' | 'prepared' | 'preimage-retained' | 'published' {
  if (!/^[a-f0-9-]{36}$/u.test(publication.transactionId) || !Number.isInteger(publication.index) ||
      publication.index < 0 || publication.index > 127 || publication.relative.includes('\\') ||
      publication.relative.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    throw new WindowsPrivateStateError('publication-intent');
  }
  const target = operationPath(scope, path.join(scope.root, publication.relative));
  const stage = operationPath(scope, `${target}.msn-${publication.transactionId}`);
  const backup = operationPath(scope, `${stage}.before`);
  const intent = operationPath(scope, path.join(scope.root, '.missionspec', 'transactions', `${publication.transactionId}.win-${publication.index}.json`));
  if (!inspect && scope.lease === undefined) throw new WindowsPrivateStateError('writer-lease');
  const value = invokeWindowsHelper({ operation: {
    ...operationScope(scope), kind: inspect ? 'inspect-publication' : 'publish',
    path: target, stage, backup, intent, relative: publication.relative,
    plan: operationDigest(publication.plan), expected: publication.expected === 'absent' ? 'absent' : operationDigest(publication.expected),
    proposed: operationDigest(publication.proposed),
    ...(publication.stageIdentity === undefined ? {} : { stageIdentity: {
      device: String(publication.stageIdentity.dev), inode: String(publication.stageIdentity.ino),
    } }),
  } });
  const state: unknown = typeof value === 'object' && value !== null ? Reflect.get(value, 'state') : undefined;
  if (state !== 'absent' && state !== 'prepared' && state !== 'preimage-retained' && state !== 'published') {
    throw new WindowsPrivateStateError('publication-state');
  }
  return state;
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

/** Read-only validation of the fixed OS host and its ancestor ACLs; no workspace or process effect. */
export function validateWindowsSystemHost(): void {
  requireWindowsPrivateState();
  invokeWindowsHelper({ kind: 'validate-system-host' });
}

/** Private-entry checks and the separately requested, identity-guarded directory barrier; never authority. */
export function windowsPrivateEntries(entries: readonly WindowsPrivateEntry[], lease?: WindowsWriterLease): void {
  requireWindowsPrivateState();
  if (entries.length === 0 || entries.length > 8) throw new WindowsPrivateStateError();
  for (const entry of entries) {
    validateWindowsStatePath(entry.path);
    for (const template of [entry.copySecurityFrom, entry.sameSecurityAs]) {
      if (template !== undefined) {
        validateWindowsStatePath(template);
        if (entry.directory || entry.ordinaryFile !== true || template === entry.path || path.dirname(template) !== path.dirname(entry.path)) {
          throw new WindowsPrivateStateError('file-security');
        }
      }
    }
    if (entry.copySecurityFrom !== undefined && entry.create !== true) throw new WindowsPrivateStateError('file-security');
    if (entry.flushIdentity !== undefined && (entry.directory !== true || entry.writable !== true || entry.create === true ||
        typeof entry.flushIdentity.device !== 'string' || !/^(?:0|[1-9][0-9]{0,9})$/u.test(entry.flushIdentity.device) ||
        BigInt(entry.flushIdentity.device) > 0xffff_ffffn ||
        typeof entry.flushIdentity.inode !== 'string' || !/^[1-9][0-9]{0,19}$/u.test(entry.flushIdentity.inode) ||
        BigInt(entry.flushIdentity.inode) > 0xffff_ffff_ffff_ffffn)) {
      throw new WindowsPrivateStateError('flush-options');
    }
  }
  if (lease !== undefined) {
    validateWindowsStatePath(lease.path);
    const root = path.dirname(path.dirname(lease.path));
    if (path.basename(lease.path) !== 'transaction.lock' || path.basename(path.dirname(lease.path)) !== '.missionspec' ||
        typeof lease.dev !== 'bigint' || lease.dev < 0n || lease.dev > 0xffff_ffffn ||
        typeof lease.ino !== 'bigint' || lease.ino <= 0n || lease.ino > 0xffff_ffff_ffff_ffffn ||
        !/^sha256:[a-f0-9]{64}$/u.test(lease.digest) ||
        entries.some((entry) => entry.path !== root && !entry.path.startsWith(`${root}${path.sep}`))) {
      throw new WindowsPrivateStateError('writer-lease');
    }
  }
  invokeWindowsHelper({ entries, ...(lease === undefined ? {} : {
    lease: { path: lease.path, device: lease.dev.toString(), inode: lease.ino.toString(), digest: lease.digest,
      ...(lease.process === undefined ? {} : { process: parseWindowsProcessInstance(lease.process) }) },
  }) });
}

/** Cooperative writer recovery only: absence of one PID is not host/descendant quiescence. */
export function requireWindowsProcessAbsent(pid: number): void {
  requireWindowsPrivateState();
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 2147483647) throw new WindowsPrivateStateError('process-inspection');
  invokeWindowsHelper({ entries: [], absentProcess: pid });
}

function invokeWindowsHelper(input: object, maxBuffer = 16_384): unknown {
  validateSystemPowerShell();
  const result = spawnSync(systemPowerShell, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-File', helper,
  ], {
    input: `${JSON.stringify(input)}\n${Object.hasOwn(input, 'operation') ? 'continue\n'.repeat(32) : ''}`, encoding: 'utf8', windowsHide: true,
    timeout: 20_000, maxBuffer, shell: false,
  });
  const lines = result.stdout.trim().split(/\r?\n/u);
  const last = lines.pop() ?? '';
  const phases = new Set(['created-held', 'file-written', 'read-held', 'sqlite-header-read', 'delete-held', 'publication-held', 'intent-durable', 'preimage-renamed',
    'preimage-retained', 'source-published', 'publication-durable', 'preimage-delete-held']);
  let value: unknown;
  try {
    for (const line of lines) {
      const progress: unknown = JSON.parse(line);
      if (typeof progress !== 'object' || progress === null || Object.keys(progress).length !== 1 ||
          !phases.has(String(Reflect.get(progress, 'phase')))) throw new Error('Unexpected helper output');
    }
    const response: unknown = JSON.parse(last);
    if (result.error === undefined && result.status === 0 && typeof response === 'object' && response !== null &&
        Reflect.get(response, 'ok') === true && Object.keys(response).every((key) => key === 'ok' || key === 'value')) {
      value = Reflect.get(response, 'value');
      return value;
    }
  } catch { /* Invalid or partial output never confirms a native effect. */ }
  {
    try {
      const output: unknown = JSON.parse(last);
      throw new WindowsPrivateStateError(output);
    } catch (error) { if (error instanceof WindowsPrivateStateError) throw error; }
    throw new WindowsPrivateStateError();
  }
}
