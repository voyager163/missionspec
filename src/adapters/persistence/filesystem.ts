import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, type Stats,
} from 'node:fs';
import path from 'node:path';
import { parseWorkspaceBinding, type WorkspaceBinding } from '../../kernel/revisions.js';
import { ContractError, integer, oneOf, record, text } from '../../kernel/validation.js';
import { StoreFailure } from './failures.js';
import { requireWindowsPrivateState, validateWindowsStatePath, windowsPrivateEntries } from '../platform/windows-private-state.js';

export interface RuntimeStoreOptions {
  readonly directory: string;
  readonly expectedWorkspace: WorkspaceBinding;
  readonly mode: 'create' | 'read-only' | 'read-write';
  readonly busyTimeoutMs?: number;
}

export interface StoreFiles {
  readonly directory: string;
  readonly filename: string;
  readonly directoryIdentity: Stats;
  readonly identity: Stats;
  readonly writable: boolean;
}

export function parseOptions(value: unknown): Required<RuntimeStoreOptions> {
  const input = record(value, 'runtimeStore', ['directory', 'expectedWorkspace', 'mode', 'busyTimeoutMs']);
  const directory = text(input.directory, 'runtimeStore.directory', 4096);
  if (!path.isAbsolute(directory) || directory === path.parse(directory).root ||
      path.normalize(directory) !== directory || directory.includes('\0') || (process.platform !== 'win32' && directory.includes('\\')) ||
      directory.split(path.sep).some((part) => part === '.' || part === '..')) {
    throw new ContractError('runtimeStore.directory', 'expected a normalized absolute private directory path');
  }
  if (process.platform === 'win32') validateWindowsStatePath(directory);
  if (path.basename(directory) !== 'state' || path.basename(path.dirname(directory)) !== '.missionspec') {
    throw new StoreFailure('incompatible', 'Only .missionspec/state/ledger.sqlite is supported; prototype paths are not migrated.');
  }
  return {
    directory,
    expectedWorkspace: parseWorkspaceBinding(input.expectedWorkspace),
    mode: oneOf(input.mode, ['create', 'read-only', 'read-write'], 'runtimeStore.mode'),
    busyTimeoutMs: input.busyTimeoutMs === undefined ? 100
      : integer(input.busyTimeoutMs, 'runtimeStore.busyTimeoutMs', 0, 1000),
  };
}

function exists(filename: string): Stats | undefined {
  try {
    return lstatSync(filename);
  } catch (error) {
    if (typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT') return undefined;
    throw error;
  }
}

function checkAncestors(directory: string): void {
  let current = path.parse(directory).root;
  const ancestors = [current];
  for (const part of directory.slice(current.length).split(path.sep)) {
    if (part === '') continue;
    current = path.join(current, part);
    ancestors.push(current);
  }
  let parentWritable = false;
  for (const ancestor of ancestors) {
    const stat = lstatSync(ancestor);
    const trustedOwner = stat.uid === 0 || stat.uid === process.getuid?.();
    const writable = (stat.mode & 0o022) !== 0;
    const protectedSticky = (stat.mode & 0o1000) !== 0 && trustedOwner;
    if (!stat.isDirectory() || stat.isSymbolicLink() || (writable && !protectedSticky) ||
        (parentWritable && !trustedOwner)) {
      throw new StoreFailure('unavailable',
        'Writable ancestors require a root/current-user-owned sticky directory and a root/current-user-owned child; symlinks are unsupported.');
    }
    parentWritable = writable;
  }
}

function checkPrivate(stat: Stats, directory: boolean, writable: boolean): void {
  const required = directory ? (writable ? 0o700 : 0o500) : (writable ? 0o600 : 0o400);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile()) ||
      stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0 ||
      (stat.mode & required) !== required || (!directory && stat.nlink !== 1)) {
    throw new StoreFailure('unavailable', 'Runtime store requires an owner-only directory and single-link owner-only regular file.');
  }
}

function checkSidecars(filename: string): void {
  for (const suffix of ['-journal', '-wal', '-shm']) {
    if (exists(`${filename}${suffix}`) !== undefined) {
      throw new StoreFailure('busy', 'Runtime store has a journal or WAL sidecar; automatic recovery is not performed.');
    }
  }
}

function sameFile(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function rejectPrototypeDirectory(directory: string): void {
  const prototypeDirectory = path.join(path.dirname(path.dirname(directory)), '.missionspec-runtime');
  if (exists(prototypeDirectory) !== undefined) {
    throw new StoreFailure('incompatible', 'An older prototype runtime-store directory exists; no migration is performed.');
  }
}

function rejectPrototypeFiles(directory: string): void {
  if (['', '-journal', '-wal', '-shm'].some((suffix) =>
    exists(path.join(directory, `runtime.sqlite${suffix}`)) !== undefined)) {
    throw new StoreFailure('incompatible', 'An older prototype runtime-store path exists; no migration or parallel initialization is performed.');
  }
}

export function requireSupportedPlatform(): void {
  if (process.platform === 'win32') { requireWindowsPrivateState(); return; }
  if ((process.platform !== 'darwin' && process.platform !== 'linux') || process.getuid === undefined) {
    throw new StoreFailure('unavailable',
      'Owner-only filesystem permissions require local POSIX semantics; Windows ACL handling is not qualified.');
  }
}

export function prepareFiles(options: Required<RuntimeStoreOptions>): StoreFiles {
  requireSupportedPlatform();
  if (process.platform === 'win32') {
    const writable = options.mode !== 'read-only';
    rejectPrototypeDirectory(options.directory);
    rejectPrototypeFiles(options.directory);
    windowsPrivateEntries([{ path: path.dirname(options.directory), directory: true, writable }]);
    if (options.mode === 'create' && exists(options.directory) === undefined) {
      windowsPrivateEntries([{ path: options.directory, directory: true, writable: true, create: true }]);
    }
    const directoryIdentity = lstatSync(options.directory);
    windowsPrivateEntries([{ path: options.directory, directory: true, writable }]);
    const filename = path.join(options.directory, 'ledger.sqlite');
    checkSidecars(filename);
    if (options.mode === 'create') {
      if (exists(filename) !== undefined) throw new StoreFailure('conflict', 'Exclusive runtime store creation found an existing path.');
      windowsPrivateEntries([{ path: filename, directory: false, writable: true, create: true }]);
    }
    const identity = lstatSync(filename);
    windowsPrivateEntries([{ path: filename, directory: false, writable }]);
    const files = { directory: options.directory, filename, directoryIdentity, identity, writable };
    if (options.mode !== 'create') checkFiles(files);
    return files;
  }
  checkAncestors(path.dirname(path.dirname(options.directory)));
  rejectPrototypeDirectory(options.directory);
  checkAncestors(path.dirname(options.directory));
  const writable = options.mode !== 'read-only';
  const existingDirectory = exists(options.directory);
  if (existingDirectory !== undefined) checkPrivate(existingDirectory, true, writable);
  rejectPrototypeFiles(options.directory);
  if (options.mode === 'create' && existingDirectory === undefined) {
    mkdirSync(options.directory, { mode: 0o700 });
  }
  const directoryIdentity = lstatSync(options.directory);
  checkPrivate(directoryIdentity, true, writable);
  const filename = path.join(options.directory, 'ledger.sqlite');
  checkSidecars(filename);
  if (options.mode === 'create') {
    const descriptor = openSync(filename, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR |
      constants.O_NOFOLLOW, 0o600);
    closeSync(descriptor);
  }
  const identity = lstatSync(filename);
  checkPrivate(identity, false, writable);
  const files = { directory: options.directory, filename, directoryIdentity, identity, writable };
  if (options.mode !== 'create') checkFiles(files);
  return files;
}

export function checkFiles(files: StoreFiles): void {
  if (process.platform === 'win32') {
    windowsPrivateEntries([
      { path: path.dirname(files.directory), directory: true, writable: files.writable },
      { path: files.directory, directory: true, writable: files.writable },
      { path: files.filename, directory: false, writable: files.writable },
    ]);
  } else checkAncestors(path.dirname(files.directory));
  const directory = lstatSync(files.directory);
  const file = lstatSync(files.filename);
  if (process.platform !== 'win32') {
    checkPrivate(directory, true, files.writable);
    checkPrivate(file, false, files.writable);
  }
  if (!sameFile(directory, files.directoryIdentity) || !sameFile(file, files.identity)) {
    throw new StoreFailure('unavailable', 'Runtime store path identity changed; reopen explicitly after review.');
  }
  rejectPrototypeDirectory(files.directory);
  rejectPrototypeFiles(files.directory);
  checkSidecars(files.filename);
  const descriptor = openSync(files.filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    if (!sameFile(fstatSync(descriptor), files.identity)) {
      throw new StoreFailure('unavailable', 'Runtime store file changed while being opened.');
    }
    const header = Buffer.alloc(100);
    if (readSync(descriptor, header, 0, header.length, 0) !== header.length ||
        header.subarray(0, 16).toString('ascii') !== 'SQLite format 3\0') {
      throw new StoreFailure('corrupt', 'Runtime store has an invalid SQLite header.');
    }
    if (header[18] !== 1 || header[19] !== 1) {
      throw new StoreFailure('incompatible', 'Only rollback/DELETE-journal runtime stores are supported; WAL is not ignored.');
    }
  } finally {
    closeSync(descriptor);
  }
}
