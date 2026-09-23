import { lstatSync, readFileSync, readdirSync, readlinkSync } from 'node:fs';
import path from 'node:path';

export function powerShellStartupCache(profile) {
  return path.join(profile, 'AppData', 'Local', 'Microsoft', 'Windows', 'PowerShell', 'StartupProfileData-NonInteractive');
}

export function observabilityFixtureSnapshot(root, { profile } = {}) {
  const cache = profile === undefined ? undefined : powerShellStartupCache(profile);
  function snapshot(filename) {
    const info = lstatSync(filename, { bigint: true });
    const metadata = { mode: String(info.mode), device: String(info.dev), inode: String(info.ino), links: String(info.nlink) };
    if (filename === cache) {
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n || info.size !== 64n) {
        throw new Error('Unexpected PowerShell startup-cache type, links or size');
      }
      // Only this OS-runtime 64-byte cache may update content/mtime. Its identity,
      // mode and every other profile entry remain part of the exact snapshot.
      return { ...metadata, runtimeCache: 'powershell-startup-profile', size: 64 };
    }
    const exact = { ...metadata, mtime: String(info.mtimeNs) };
    if (info.isSymbolicLink()) return { ...exact, link: readlinkSync(filename) };
    if (!info.isDirectory()) return { ...exact, bytes: readFileSync(filename).toString('base64') };
    return { ...exact, entries: Object.fromEntries(
      readdirSync(filename).sort().map((name) => [name, snapshot(path.join(filename, name))]),
    ) };
  }
  return snapshot(root);
}
