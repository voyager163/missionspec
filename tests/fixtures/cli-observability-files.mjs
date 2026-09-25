import path from 'node:path';
import { fixtureTreeSnapshot } from './filesystem-snapshot.mjs';

export function powerShellStartupCache(profile) {
  return path.join(profile, 'AppData', 'Local', 'Microsoft', 'Windows', 'PowerShell', 'StartupProfileData-NonInteractive');
}

export function observabilityFixtureSnapshot(root, { profile } = {}) {
  const cache = profile === undefined ? undefined : powerShellStartupCache(profile);
  const observed = fixtureTreeSnapshot(root, {
    validateEntry(filename, info) {
      if (filename === cache && (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n || info.size !== 64n)) {
        throw new Error('Unexpected PowerShell startup-cache type, links or size');
      }
    },
  });
  function snapshot(filename, entry) {
    const info = entry.stat;
    const metadata = { mode: String(info.mode), device: String(info.dev), inode: String(info.ino), links: String(info.nlink) };
    if (filename === cache) {
      // Only this OS-runtime 64-byte cache may update content/mtime. Its identity,
      // mode and every other profile entry remain part of the exact snapshot.
      return { ...metadata, runtimeCache: 'powershell-startup-profile', size: 64 };
    }
    const exact = { ...metadata, mtime: String(info.mtimeNs) };
    if (info.isSymbolicLink()) return { ...exact, link: entry.link };
    if (!info.isDirectory()) return { ...exact, bytes: entry.bytes.toString('base64') };
    return { ...exact, entries: Object.fromEntries(
      Object.entries(entry.entries).map(([name, child]) => [name, snapshot(path.join(filename, name), child)]),
    ) };
  }
  return snapshot(root, observed);
}
