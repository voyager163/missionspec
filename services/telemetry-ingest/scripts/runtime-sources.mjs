import { createHash, randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createGunzip, crc32 } from 'node:zlib';

const MAX_ARTIFACT = 512 * 1024 * 1024;
const MAX_TOTAL = 1024 * 1024 * 1024;
const roles = new Set(['debian-source', 'node-source', 'node-distribution', 'release-checksums', 'release-signature', 'assembly-source', 'assembly-license']);
const sha256 = data => createHash('sha256').update(data).digest('hex');
const json = data => `${JSON.stringify(data, null, 2)}\n`;
const fail = message => { throw new Error(message); };
const check = (condition, message) => { if (!condition) fail(message); };
const hashPattern = /^[a-f0-9]{64}$/;

function keys(value, expected, label) {
  check(value && typeof value === 'object' && !Array.isArray(value), `Invalid ${label}`);
  check(Object.keys(value).sort().join(',') === [...expected].sort().join(','), `Unexpected/missing ${label} fields`);
}
function text(value, label) {
  check(typeof value === 'string' && value.length > 0 && value.length < 4096 && !/[\x00-\x1f\x7f]/.test(value), `Invalid ${label}`);
}
export function safePath(value) {
  text(value, 'path');
  check(!value.startsWith('/') && value.split('/').every(part => /^[a-zA-Z0-9_+@.,=~-]+$/.test(part) && part !== '.' && part !== '..'), 'Unsafe local path');
  return value;
}
function filename(value) {
  safePath(value);
  check(!value.includes('/') && !value.startsWith('-'), 'Unsafe filename');
}
function identity(value) {
  text(value, 'image identity');
  check(/^[a-z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(value), 'Image identity must be digest-pinned');
}
export function validateUrl(value) {
  text(value, 'URL');
  const u = new URL(value);
  check(u.protocol === 'https:' && !u.username && !u.password && !u.port && !u.search && !u.hash, 'Only credential-free pinned HTTPS URLs are allowed');
  const allowed =
    (u.hostname === 'snapshot.debian.org' && /^\/file\/[a-f0-9]{40}$/.test(u.pathname)) ||
    (u.hostname === 'nodejs.org' && /^\/dist\/v\d+\.\d+\.\d+\/(?:node-v\d+\.\d+\.\d+(?:-linux-x64)?\.tar\.gz|SHASUMS256\.txt(?:\.asc)?)$/.test(u.pathname)) ||
    (u.hostname === 'codeload.github.com' && /^\/GoogleContainerTools\/distroless\/tar\.gz\/[a-f0-9]{40}$/.test(u.pathname)) ||
    (u.hostname === 'raw.githubusercontent.com' && /^\/GoogleContainerTools\/distroless\/[a-f0-9]{40}\/LICENSE$/.test(u.pathname));
  check(allowed && u.href === value, 'Unapproved or unpinned public source URL');
}
function integrity(record) {
  check(hashPattern.test(record.sha256) && Number.isSafeInteger(record.size) && record.size > 0 && record.size <= MAX_ARTIFACT, 'Invalid SHA256 or byte length');
}
export function parseControl(input) {
  const fields = {};
  let current;
  for (let line of input.replaceAll('\r\n', '\n').split('\n')) {
    if (line.startsWith('- ')) line = line.slice(2);
    if (/^\s/.test(line) && current) {
      fields[current] += `\n${line}`;
    } else if (/^[A-Za-z][A-Za-z0-9-]*:/.test(line)) {
      current = line.slice(0, line.indexOf(':'));
      check(!(current in fields), `Duplicate control field ${current}`);
      fields[current] = line.slice(line.indexOf(':') + 1).trim();
    } else {
      current = undefined;
    }
  }
  return fields;
}
export function packageFromStatus(data) {
  const fields = parseControl(data);
  const source = /^(.*?) \((.*?)\)$/.exec(fields.Source || '');
  return {
    name: fields.Package, version: fields.Version, architecture: fields.Architecture,
    source: source?.[1] || fields.Source || fields.Package,
    sourceVersion: source?.[2] || fields.Version,
  };
}
export function validateLock(lock) {
  keys(lock, ['schemaVersion', 'platform', 'identities', 'node', 'distroless', 'packages', 'sources', 'artifacts', 'files', 'blobs', 'provenanceLimits'], 'lock');
  check(lock.schemaVersion === 1 && lock.platform === 'linux/amd64', 'Unsupported runtime source lock');
  keys(lock.identities, ['runtimeBase', 'runtimeBaseIndexDigest', 'nodeBuildBase', 'candidateImageId'], 'identities');
  identity(lock.identities.runtimeBase);
  identity(lock.identities.nodeBuildBase);
  for (const key of ['runtimeBaseIndexDigest', 'candidateImageId']) check(/^sha256:[a-f0-9]{64}$/.test(lock.identities[key]), `Invalid ${key}`);
  check(Array.isArray(lock.artifacts) && lock.artifacts.length > 0 && lock.artifacts.length <= 128, 'Invalid artifact count');
  const artifacts = new Map();
  let total = 0;
  for (const a of lock.artifacts) {
    keys(a, ['filename', 'url', 'sha256', 'size', 'role'], 'artifact');
    filename(a.filename); validateUrl(a.url); integrity(a);
    check(roles.has(a.role) && !artifacts.has(a.filename), 'Duplicate artifact or unknown role');
    artifacts.set(a.filename, a); total += a.size;
  }
  check(total <= MAX_TOTAL, 'Source lock exceeds download budget');
  check(lock.blobs && typeof lock.blobs === 'object' && !Array.isArray(lock.blobs), 'Invalid notice blobs');
  const decoded = new Map();
  let inlineTotal = 0;
  for (const [digest, encoded] of Object.entries(lock.blobs)) {
    check(hashPattern.test(digest) && typeof encoded === 'string' && encoded.length <= 8 * 1024 * 1024, 'Invalid inline blob');
    const bytes = Buffer.from(encoded, 'base64');
    check(bytes.toString('base64') === encoded && sha256(bytes) === digest, 'Inline notice checksum mismatch');
    inlineTotal += bytes.length;
    check(inlineTotal <= 8 * 1024 * 1024, 'Inline notice budget exceeded');
    decoded.set(digest, bytes);
  }
  check(Array.isArray(lock.files) && lock.files.length <= 256, 'Invalid locked files');
  const files = new Map(), usedBlobs = new Set();
  for (const f of lock.files) {
    keys(f, ['path', 'sha256', 'size'], 'file');
    safePath(f.path); integrity(f);
    check(!files.has(f.path) && decoded.get(f.sha256)?.length === f.size, 'Duplicate or missing locked file');
    files.set(f.path, decoded.get(f.sha256)); usedBlobs.add(f.sha256);
  }
  check(usedBlobs.size === decoded.size, 'Unreferenced notice blob');
  const baseDigest = lock.identities.runtimeBase.split('@sha256:')[1];
  const indexDigest = lock.identities.runtimeBaseIndexDigest.slice(7);
  const manifestBytes = files.get('provenance/distroless-manifest.json');
  const configBytes = files.get('provenance/distroless-config.json');
  const indexBytes = files.get('provenance/distroless-index.json');
  check(manifestBytes && configBytes && indexBytes, 'Missing immutable base provenance');
  check(sha256(manifestBytes) === baseDigest && sha256(indexBytes) === indexDigest, 'OCI base identity mismatch');
  const manifest = JSON.parse(manifestBytes), config = JSON.parse(configBytes), index = JSON.parse(indexBytes);
  check(manifest.config.digest === `sha256:${sha256(configBytes)}` && manifest.config.size === configBytes.length, 'OCI config identity mismatch');
  check(config.os === 'linux' && config.architecture === 'amd64', 'OCI base platform mismatch');
  check(index.manifests.some(m => m.digest === `sha256:${baseDigest}` && m.platform?.os === 'linux' && m.platform?.architecture === 'amd64'), 'Base index does not cover the pinned platform');
  check(Array.isArray(lock.sources) && lock.sources.length > 0, 'Missing Debian source closure');
  const sources = new Map(), usedArtifacts = new Set();
  function use(name, role) {
    const artifact = artifacts.get(name);
    check(artifact?.role === role && !usedArtifacts.has(name), `Missing, reused, or misclassified artifact ${name}`);
    usedArtifacts.add(name);
    return artifact;
  }
  for (const s of lock.sources) {
    keys(s, ['name', 'version', 'snapshotApi', 'dsc', 'artifacts'], 'Debian source');
    check(/^[a-z0-9][a-z0-9+.-]*$/.test(s.name), 'Invalid source package');
    text(s.version, 'source version');
    check(s.snapshotApi === `https://snapshot.debian.org/mr/package/${s.name}/${encodeURIComponent(s.version)}/srcfiles`, 'Invalid snapshot provenance');
    const key = `${s.name}@${s.version}`;
    check(!sources.has(key) && Array.isArray(s.artifacts) && s.artifacts.length >= 2 && s.artifacts.includes(s.dsc) && s.dsc.endsWith('.dsc'), 'Invalid/duplicate source closure');
    for (const a of s.artifacts) use(a, 'debian-source');
    check(s.artifacts.filter(a => a.endsWith('.dsc')).length === 1, 'Source closure must have one dsc');
    sources.set(key, s);
  }
  check(Array.isArray(lock.packages) && lock.packages.length > 0, 'Missing runtime packages');
  const packageNames = new Set(), usedSources = new Set();
  for (const p of lock.packages) {
    keys(p, ['name', 'version', 'architecture', 'source', 'sourceVersion', 'metadataPath', 'copyrightPath', 'binaryProvenance'], 'package');
    check(/^[a-z0-9][a-z0-9+.-]*$/.test(p.name) && !packageNames.has(p.name), 'Invalid/duplicate runtime package');
    check(p.metadataPath === `runtime/var/lib/dpkg/status.d/${p.name}` && p.copyrightPath === `runtime/usr/share/doc/${p.name}/copyright`, 'Wrong package notice/metadata path');
    check(files.has(p.metadataPath) && files.has(p.copyrightPath), `Missing package metadata/notice ${p.name}`);
    const actual = packageFromStatus(files.get(p.metadataPath).toString('utf8'));
    for (const key of ['name', 'version', 'architecture', 'source', 'sourceVersion']) check(actual[key] === p[key], `Package metadata mismatch ${p.name}:${key}`);
    check(['amd64', 'all'].includes(p.architecture), 'Wrong runtime architecture');
    const source = `${p.source}@${p.sourceVersion}`;
    check(sources.has(source), `Missing exact source version ${source}`);
    keys(p.binaryProvenance, ['url', 'sha256', 'assemblyRevision'], 'binary provenance');
    check(/^https:\/\/snapshot\.debian\.org\/archive\/debian(?:-security)?\/\d{8}T\d{6}Z\/pool\/(?:updates\/)?main\/[a-z0-9+/.-]+\/[a-zA-Z0-9+_.~%-]+\.deb$/.test(p.binaryProvenance.url), 'Unpinned binary provenance');
    check(hashPattern.test(p.binaryProvenance.sha256) && /^[a-f0-9]{40}$/.test(p.binaryProvenance.assemblyRevision), 'Invalid binary provenance');
    packageNames.add(p.name); usedSources.add(source);
  }
  check(usedSources.size === sources.size, 'Unneeded Debian source version');
  const statuses = [...files.keys()].filter(p => p.startsWith('runtime/var/lib/dpkg/status.d/'));
  check(statuses.length === packageNames.size && statuses.every(p => packageNames.has(p.split('/').at(-1))), 'Uncovered runtime package metadata');
  for (const name of ['GPL-2', 'GPL-3', 'LGPL-2.1', 'LGPL-3', 'Apache-2.0']) check(files.has(`runtime/usr/share/common-licenses/${name}`), `Missing common license ${name}`);
  keys(lock.node, ['version', 'binaryPath', 'binarySha256', 'binarySize', 'licensePath', 'licenseSha256', 'sourceArtifact', 'distributionArtifact', 'shasumsArtifact', 'signatureArtifact'], 'Node');
  const n = lock.node;
  check(/^\d+\.\d+\.\d+$/.test(n.version) && n.binaryPath === '/usr/local/bin/node' && n.licensePath === 'runtime/usr/share/doc/node/LICENSE', 'Invalid Node identity');
  integrity({ sha256: n.binarySha256, size: n.binarySize });
  check(sha256(files.get(n.licensePath) || '') === n.licenseSha256, 'Missing Node license');
  for (const [name, role] of [[n.sourceArtifact, 'node-source'], [n.distributionArtifact, 'node-distribution'], [n.shasumsArtifact, 'release-checksums'], [n.signatureArtifact, 'release-signature']]) {
    check(use(name, role).url.startsWith(`https://nodejs.org/dist/v${n.version}/`), 'Node release version mismatch');
  }
  keys(lock.distroless, ['revision', 'sourceArtifact', 'licenseArtifact', 'provenance'], 'distroless');
  const d = lock.distroless;
  check(/^[a-f0-9]{40}$/.test(d.revision), 'Invalid assembly revision');
  text(d.provenance, 'assembly provenance');
  check(use(d.sourceArtifact, 'assembly-source').url === `https://codeload.github.com/GoogleContainerTools/distroless/tar.gz/${d.revision}`, 'Unpinned assembly source');
  check(use(d.licenseArtifact, 'assembly-license').url === `https://raw.githubusercontent.com/GoogleContainerTools/distroless/${d.revision}/LICENSE`, 'Unpinned assembly license');
  check(lock.packages.every(p => p.binaryProvenance.assemblyRevision === d.revision), 'Assembly revision mismatch');
  check(usedArtifacts.size === artifacts.size, 'Unreferenced public source artifact');
  check(Array.isArray(lock.provenanceLimits) && lock.provenanceLimits.length > 0, 'Missing provenance limits');
  for (const limit of lock.provenanceLimits) text(limit, 'provenance limit');
  return { artifacts, files };
}

export async function verifyFile(file, expected) {
  const stat = await fs.lstat(file);
  check(stat.isFile() && !stat.isSymbolicLink() && stat.size === expected.size, `File type/length mismatch: ${path.basename(file)}`);
  const h = createHash('sha256');
  for await (const chunk of createReadStream(file)) h.update(chunk);
  check(h.digest('hex') === expected.sha256, `SHA256 mismatch: ${path.basename(file)}`);
}

export async function acquireArtifact(artifact, cache, download = false, request = fetch) {
  filename(artifact.filename); validateUrl(artifact.url); integrity(artifact);
  const destination = path.join(cache, artifact.filename);
  try {
    await verifyFile(destination, artifact);
    return destination;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  check(download, `Missing cached artifact ${artifact.filename}; use --download explicitly`);
  const partial = `${destination}.${randomUUID()}.part`;
  const controller = new AbortController();
  try {
    const response = await request(artifact.url, {
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(180000)]), redirect: 'error', credentials: 'omit',
      headers: { 'accept-encoding': 'identity' },
    });
    check(response.status === 200 && response.body, `Public download failed for ${artifact.filename}`);
    const length = response.headers.get('content-length');
    check(length === null || Number(length) === artifact.size, `HTTP byte length mismatch: ${artifact.filename}`);
    let received = 0;
    const h = createHash('sha256');
    await pipeline(Readable.fromWeb(response.body), new Transform({
      transform(chunk, _encoding, done) {
        received += chunk.length;
        if (received > artifact.size) return done(new Error(`Download exceeds locked length: ${artifact.filename}`));
        h.update(chunk); done(null, chunk);
      },
    }), createWriteStream(partial, { flags: 'wx', mode: 0o600 }));
    check(received === artifact.size && h.digest('hex') === artifact.sha256, `Download integrity mismatch: ${artifact.filename}`);
    await fs.rename(partial, destination);
    return destination;
  } finally {
    controller.abort();
    await fs.rm(partial, { force: true });
  }
}

export function verifyDsc(source, input, artifacts) {
  const fields = parseControl(input);
  check(fields.Source === source.name && fields.Version === source.version, `DSC source/version mismatch: ${source.dsc}`);
  const entries = (fields['Checksums-Sha256'] || '').trim().split('\n').filter(Boolean).map(line => {
    const match = /^\s*([a-f0-9]{64})\s+(\d+)\s+(\S+)\s*$/.exec(line);
    check(match, 'Invalid DSC SHA256 table');
    filename(match[3]);
    return { filename: match[3], sha256: match[1], size: Number(match[2]) };
  });
  const expected = source.artifacts.filter(a => a !== source.dsc);
  check(entries.length === expected.length && new Set(entries.map(e => e.filename)).size === entries.length, 'Incomplete/duplicate DSC source files');
  for (const entry of entries) {
    const a = artifacts.get(entry.filename);
    check(expected.includes(entry.filename) && a?.sha256 === entry.sha256 && a?.size === entry.size, `DSC checksum/coverage mismatch: ${entry.filename}`);
  }
}

// Inspect selected members without extracting upstream archives or executing their contents.
export async function inspectTarGzip(file, targets) {
  const input = createReadStream(file), stream = input.pipe(createGunzip());
  input.on('error', error => stream.destroy(error));
  const iterator = stream[Symbol.asyncIterator]();
  let buffer = Buffer.alloc(0), ended = false, inflated = 0;
  async function consume(length, visit) {
    let remaining = length;
    while (remaining > 0) {
      if (!buffer.length) {
        const next = await iterator.next();
        check(!next.done, 'Truncated upstream tar');
        buffer = next.value; inflated += buffer.length;
        check(inflated <= 2 * MAX_TOTAL, 'Upstream tar inflation budget exceeded');
      }
      const n = Math.min(remaining, buffer.length);
      visit?.(buffer.subarray(0, n));
      buffer = buffer.subarray(n); remaining -= n;
    }
  }
  const found = new Map();
  let longName, paxName;
  try {
    while (!ended) {
      const header = Buffer.alloc(512);
      let offset = 0;
      await consume(512, chunk => { chunk.copy(header, offset); offset += chunk.length; });
      if (header.every(v => v === 0)) { ended = true; break; }
      const str = (start, length) => header.subarray(start, start + length).toString('utf8').replace(/\0.*$/s, '');
      const octal = str(124, 12).trim();
      check(/^[0-7]+$/.test(octal), 'Unsupported upstream tar size');
      const size = parseInt(octal, 8);
      check(Number.isSafeInteger(size) && size <= MAX_TOTAL, 'Unsafe upstream tar member size');
      const storedChecksum = parseInt(str(148, 8).trim(), 8);
      const checksum = header.reduce((sum, byte, i) => sum + (i >= 148 && i < 156 ? 32 : byte), 0);
      check(checksum === storedChecksum, 'Invalid upstream tar checksum');
      const rawName = `${str(345, 155) ? `${str(345, 155)}/` : ''}${str(0, 100)}`;
      const type = str(156, 1), name = paxName || longName || rawName;
      const target = targets[name];
      if (type === 'L' || type === 'x' || type === 'g') {
        check(size <= 65536, 'Oversized upstream tar metadata');
        const chunks = [];
        await consume(size, chunk => chunks.push(Buffer.from(chunk)));
        const value = Buffer.concat(chunks).toString('utf8');
        if (type === 'L') longName = value.replace(/\0.*$/s, '');
        else if (type === 'x') paxName = value.match(/(?:^|\n)\d+ path=([^\n]+)\n/)?.[1];
      } else {
        longName = undefined; paxName = undefined;
        if (target) {
          check((type === '' || type === '0') && !found.has(name) && size <= target.maxBytes, 'Unsafe/duplicate upstream tar target');
          const h = createHash('sha256'), chunks = [];
          await consume(size, chunk => { h.update(chunk); if (target.capture) chunks.push(Buffer.from(chunk)); });
          found.set(name, { size, sha256: h.digest('hex'), ...(target.capture ? { bytes: Buffer.concat(chunks) } : {}) });
        } else await consume(size);
      }
      await consume((512 - size % 512) % 512);
    }
    check(Object.keys(targets).every(name => found.has(name)), 'Missing upstream tar member');
    return found;
  } finally {
    input.destroy(); stream.destroy();
  }
}

export async function verifyUpstream(lock, cache) {
  const { artifacts, files } = validateLock(lock);
  for (const source of lock.sources) verifyDsc(source, await fs.readFile(path.join(cache, source.dsc), 'utf8'), artifacts);
  const n = lock.node, prefix = `node-v${n.version}`;
  const sums = await fs.readFile(path.join(cache, n.shasumsArtifact), 'utf8');
  for (const filename of [n.sourceArtifact, n.distributionArtifact]) {
    const actual = sums.split('\n').map(line => line.trim().split(/\s+/)).filter(([, name]) => name === filename);
    check(actual.length === 1 && actual[0][0] === artifacts.get(filename).sha256, 'Node release checksum mismatch');
  }
  const binary = `${prefix}-linux-x64/bin/node`, license = `${prefix}-linux-x64/LICENSE`;
  const distribution = await inspectTarGzip(path.join(cache, n.distributionArtifact), {
    [binary]: { maxBytes: n.binarySize }, [license]: { maxBytes: 1024 * 1024 },
  });
  check(distribution.get(binary).sha256 === n.binarySha256 && distribution.get(binary).size === n.binarySize, 'Official Node binary mismatch');
  check(distribution.get(license).sha256 === n.licenseSha256, 'Official Node distribution license mismatch');
  const sourceLicense = `${prefix}/LICENSE`;
  const source = await inspectTarGzip(path.join(cache, n.sourceArtifact), { [sourceLicense]: { maxBytes: 1024 * 1024 } });
  check(source.get(sourceLicense).sha256 === n.licenseSha256, 'Official Node source license mismatch');
  const d = lock.distroless, distrolessLicense = `distroless-${d.revision}/LICENSE`;
  const assembly = await inspectTarGzip(path.join(cache, d.sourceArtifact), { [distrolessLicense]: { maxBytes: 1024 * 1024 } });
  check(assembly.get(distrolessLicense).sha256 === artifacts.get(d.licenseArtifact).sha256, 'Distroless assembly license mismatch');
  check(files.get(n.licensePath), 'Missing deployed Node license');
}

const SNAPSHOT_FILES = [
  'LICENSE', '.dockerignore', 'assets/schemas/telemetry-event.schema.json',
  'scripts/check-licenses.mjs', 'licenses/reviewed-texts.json',
  'licenses/telemetry-runtime.json', 'licenses/TELEMETRY_THIRD_PARTY_NOTICES',
  'licenses/external-service-licenses.json', 'licenses/external/nodable-entities-2.1.0/LICENSE.md',
  ...['Dockerfile', 'package.json', 'package-lock.json', 'tsconfig.json', 'scripts/schema.mjs', 'scripts/runtime-sources.mjs',
    'scripts/container-smoke.mjs', 'scripts/container-qualification.mjs']
    .map(name => `services/telemetry-ingest/${name}`),
];
const SNAPSHOT_TREES = ['src', 'schema', 'tests'].map(name => `services/telemetry-ingest/${name}`);

async function regularFile(root, relative) {
  const file = path.join(root, relative);
  const real = await fs.realpath(file), rootReal = await fs.realpath(root);
  check(real === path.join(rootReal, relative), 'Snapshot file escapes project root or uses a symlink');
  const stat = await fs.lstat(file);
  check(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 4 * 1024 * 1024, 'Unsafe source snapshot file');
  const bytes = await fs.readFile(file);
  return { path: `service/${relative}`, bytes, size: bytes.length, sha256: sha256(bytes) };
}
export async function serviceSnapshot(root) {
  const result = [];
  for (const file of SNAPSHOT_FILES) result.push(await regularFile(root, file));
  async function walk(relative) {
    for (const entry of (await fs.readdir(path.join(root, relative), { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : 1)) {
      const name = `${relative}/${entry.name}`;
      check(!entry.isSymbolicLink(), 'Symlinks are forbidden in the service snapshot');
      if (entry.isDirectory()) await walk(name);
      else {
        check(/\.(?:ts|mjs|json)$/.test(entry.name), `Unexpected service source file ${name}`);
        result.push(await regularFile(root, name));
      }
      check(result.length <= 256, 'Service source snapshot file budget exceeded');
    }
  }
  for (const tree of SNAPSHOT_TREES) await walk(tree);
  check(result.reduce((sum, file) => sum + file.size, 0) <= 16 * 1024 * 1024, 'Service source snapshot byte budget exceeded');
  return result;
}

export function notice(lock) {
  return `RUNTIME CORRESPONDING SOURCE AND NOTICES

This image carries runtime-corresponding-source.tar.gz, runtime-source-manifest.json,
and runtime-notices/. These are actual source bytes delivered with the image, not
a future source offer or a homepage link. Copy them out with your container tooling.
The archive contains the complete exact Debian source packages (.dsc and every
SHA256-listed component), official Node source, supporting distroless assembly
source, upstream notices, and the allowlisted service/build-source snapshot.

Runtime: ${lock.platform}
Base: ${lock.identities.runtimeBase}
Node: ${lock.node.version} (official linux-x64 binary SHA256 ${lock.node.binarySha256})

Debian source mapping:
${lock.packages.map(p => `  ${p.name} ${p.version} -> ${p.source} ${p.sourceVersion}`).join('\n')}

No distribution binary archive is included: the official Node linux-x64 tarball
is used only for verification. Original Node source may contain upstream tool
sources; that does not install npm, Corepack, Yarn, or Debian utilities at runtime.
Production JavaScript dependency licenses remain in the service's existing
THIRD_PARTY_NOTICES, also copied into this source snapshot; these are not relicensed.

Build and modification:
Extract this archive into a working directory. For each sources/debian/*.dsc,
use Debian's dpkg-source -x with its sibling source archives available. The
debian/rules, debian/control, patches, copyright and upstream build instructions
are in those original sources. Use a suitable Debian 13 amd64 build environment;
dpkg-buildpackage -b -us -uc runs the Debian build. Source Build-Depends still
require their own build environment; this is not a vendored compiler/sysroot.
For Node, extract sources/node/${lock.node.sourceArtifact} and follow BUILDING.md
and configure/Makefile in that exact release. For the service, restore the
service/ tree at a project root and use the included Dockerfile and package-lock;
npm ci --ignore-scripts, npm test and the documented Docker build restore its
existing build. Do not copy private operator configuration into the build context.
The distroless source includes Bazel assembly rules and Debian binary locks.

License conditions:
Preserved runtime/usr/share/doc/*/copyright, README files and common-licenses are
authoritative upstream texts, including GCC Runtime Library Exception 3.1 in the
GCC copyright files and the applicable GPL/LGPL texts. Supplying the exception
does not replace its conditions or relicense the libraries. glibc is LGPL-covered;
the shared libraries remain separate and can be rebuilt/replaced by a recipient.
Recipients may modify and reverse engineer LGPL portions for debugging their
modifications as their applicable license permits. No extra restriction is imposed
by this handoff. No installation keys, cloud credentials, or private operator
configuration are necessary to extract these sources or replace libraries locally.
Retain the applicable notices and source with redistribution. This handoff is
technical evidence, not a legal opinion or a claim of bit-identical rebuilds.

Provenance limits:
${lock.provenanceLimits.map(limit => `- ${limit}`).join('\n')}
- ${lock.distroless.provenance}
`;
}

function tarHeader(name, size) {
  safePath(name);
  const bytes = Buffer.alloc(512);
  let short = name, prefix = '';
  if (Buffer.byteLength(name) > 100) {
    const split = name.lastIndexOf('/');
    prefix = name.slice(0, split); short = name.slice(split + 1);
  }
  check(Buffer.byteLength(short) <= 100 && Buffer.byteLength(prefix) <= 155, 'Archive path exceeds ustar limits');
  bytes.write(short, 0, 100); bytes.write(prefix, 345, 155);
  const octal = (value, offset, length) => bytes.write(`${value.toString(8).padStart(length - 1, '0')}\0`, offset, length, 'ascii');
  octal(0o644, 100, 8); octal(0, 108, 8); octal(0, 116, 8);
  octal(size, 124, 12); octal(0, 136, 12);
  bytes.fill(32, 148, 156); bytes.write('0', 156);
  bytes.write('ustar\0', 257, 6); bytes.write('00', 263, 2);
  bytes.write('root', 265); bytes.write('root', 297);
  bytes.write(`${bytes.reduce((a, b) => a + b, 0).toString(8).padStart(6, '0')}\0 `, 148, 8);
  return bytes;
}
export async function writeArchive(destination, entries) {
  const sorted = [...entries].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  check(new Set(sorted.map(e => e.path)).size === sorted.length, 'Duplicate archive path');
  async function* tar() {
    for (const entry of sorted) {
      yield tarHeader(`runtime-corresponding-source/${entry.path}`, entry.size);
      const h = createHash('sha256');
      let received = 0;
      for await (const chunk of entry.bytes ? [entry.bytes] : createReadStream(entry.file)) {
        received += chunk.length; check(received <= entry.size, 'Archive input grew');
        h.update(chunk); yield chunk;
      }
      check(received === entry.size && h.digest('hex') === entry.sha256, `Archive input changed: ${entry.path}`);
      if (entry.size % 512) yield Buffer.alloc(512 - entry.size % 512);
    }
    yield Buffer.alloc(1024);
  }
  // Sources are already compressed. Fixed stored blocks avoid zlib-version-dependent output.
  async function* gzip() {
    yield Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255]);
    let block = Buffer.alloc(65535), used = 0, checksum = 0, size = 0;
    function header(length, final) {
      const value = Buffer.alloc(5);
      value[0] = final ? 1 : 0;
      value.writeUInt16LE(length, 1); value.writeUInt16LE(length ^ 0xffff, 3);
      return value;
    }
    for await (const chunk of tar()) {
      checksum = crc32(chunk, checksum); size = (size + chunk.length) >>> 0;
      let offset = 0;
      while (offset < chunk.length) {
        const count = Math.min(block.length - used, chunk.length - offset);
        chunk.copy(block, used, offset); used += count; offset += count;
        if (used === block.length) {
          yield header(used, false); yield block;
          block = Buffer.alloc(65535); used = 0;
        }
      }
    }
    yield header(used, true);
    if (used) yield block.subarray(0, used);
    const trailer = Buffer.alloc(8);
    trailer.writeUInt32LE(checksum, 0); trailer.writeUInt32LE(size, 4);
    yield trailer;
  }
  await pipeline(Readable.from(gzip()), createWriteStream(destination, { flags: 'wx', mode: 0o644 }));
}
function memoryEntry(name, bytes) {
  const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  return { path: name, bytes: value, size: value.length, sha256: sha256(value) };
}
export async function assemble({ lockPath, cache, output, projectRoot, download = false }) {
  const lockBytes = await fs.readFile(lockPath);
  check(lockBytes.length <= 12 * 1024 * 1024, 'Oversized source lock');
  const lock = JSON.parse(lockBytes), validated = validateLock(lock);
  const out = path.resolve(output), cachePath = path.resolve(cache);
  check(out !== cachePath && !cachePath.startsWith(`${out}${path.sep}`) && !out.startsWith(`${cachePath}${path.sep}`), 'Cache and output must be separate');
  await fs.mkdir(cachePath, { recursive: true });
  check((await fs.lstat(cachePath)).isDirectory() && !(await fs.lstat(cachePath)).isSymbolicLink(), 'Unsafe cache directory');
  try { await fs.lstat(out); fail('Output must not already exist'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  for (const artifact of lock.artifacts) await acquireArtifact(artifact, cachePath, download);
  await verifyUpstream(lock, cachePath);
  const entries = [memoryEntry('runtime-sources.lock.json', lockBytes), memoryEntry('NOTICE', notice(lock))];
  for (const [name, bytes] of validated.files) entries.push(memoryEntry(name, bytes));
  for (const artifact of lock.artifacts) {
    if (artifact.role === 'node-distribution') continue;
    const directory = artifact.role === 'debian-source' ? 'debian' : artifact.role.startsWith('assembly-') ? 'distroless' : 'node';
    entries.push({ path: `sources/${directory}/${artifact.filename}`, size: artifact.size, sha256: artifact.sha256, file: path.join(cachePath, artifact.filename) });
  }
  const snapshot = await serviceSnapshot(projectRoot);
  const dockerfile = snapshot.find(f => f.path === 'service/services/telemetry-ingest/Dockerfile').bytes.toString('utf8');
  const bases = dockerfile.split('\n').filter(line => /^FROM /i.test(line)).map(line => line.trim().split(/\s+/)[1]);
  check(bases.includes(lock.identities.runtimeBase) && bases.includes(lock.identities.nodeBuildBase), 'Dockerfile bases do not match the runtime source lock');
  entries.push(...snapshot, memoryEntry('service/services/telemetry-ingest/runtime-sources.lock.json', lockBytes));
  const manifest = {
    schemaVersion: 1, archiveRoot: 'runtime-corresponding-source', timestamp: '1970-01-01T00:00:00.000Z',
    platform: lock.platform, identities: lock.identities, lockSha256: sha256(lockBytes),
    packages: lock.packages, sources: lock.sources, node: lock.node, distroless: lock.distroless,
    verification: { sha256AndLengths: true, dscClosure: true, officialNodeBinaryAndBothLicenses: true, signaturesAuthenticated: false },
    provenanceLimits: lock.provenanceLimits,
    files: entries.map(({ path, size, sha256 }) => ({ path, size, sha256 })).sort((a, b) => a.path < b.path ? -1 : 1),
  };
  const manifestBytes = json(manifest);
  entries.push(memoryEntry('runtime-source-manifest.json', manifestBytes));
  const stage = `${out}.partial-${randomUUID()}`;
  await fs.mkdir(stage, { recursive: false, mode: 0o755 });
  try {
    await fs.writeFile(path.join(stage, 'runtime-source-manifest.json'), manifestBytes);
    const noticeDir = path.join(stage, 'runtime-notices');
    await fs.mkdir(noticeDir);
    await fs.writeFile(path.join(noticeDir, 'NOTICE'), notice(lock));
    for (const [name, bytes] of validated.files) {
      const target = path.join(noticeDir, name);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, bytes);
    }
    await fs.copyFile(path.join(cachePath, lock.distroless.licenseArtifact), path.join(noticeDir, 'DISTROLESS-LICENSE'));
    await fs.copyFile(path.join(projectRoot, 'licenses/TELEMETRY_THIRD_PARTY_NOTICES'), path.join(noticeDir, 'SERVICE-THIRD-PARTY-NOTICES'));
    await fs.copyFile(path.join(projectRoot, 'LICENSE'), path.join(noticeDir, 'SERVICE-LICENSE'));
    const archivePath = path.join(stage, 'runtime-corresponding-source.tar.gz');
    await writeArchive(archivePath, entries);
    const archiveHash = createHash('sha256');
    for await (const chunk of createReadStream(archivePath)) archiveHash.update(chunk);
    const receipt = {
      filename: 'runtime-corresponding-source.tar.gz', size: (await fs.stat(archivePath)).size,
      sha256: archiveHash.digest('hex'), manifestSha256: sha256(manifestBytes),
    };
    await fs.writeFile(path.join(stage, 'runtime-source-receipt.json'), json(receipt));
    await fs.rename(stage, out);
    return receipt;
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}

async function main(argv) {
  const options = { download: false };
  const names = new Map([['--lock', 'lockPath'], ['--cache', 'cache'], ['--output', 'output'], ['--project-root', 'projectRoot']]);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--download') {
      check(!options.download, 'Duplicate --download'); options.download = true;
    } else {
      const name = names.get(arg);
      check(name && !options[name] && argv[i + 1] && !argv[i + 1].startsWith('--'), 'Unknown, duplicate, or missing CLI option');
      options[name] = argv[++i];
    }
  }
  for (const name of names.values()) check(options[name], 'Usage: node runtime-sources.mjs --lock FILE --cache DIR --output NEW_DIR --project-root ROOT [--download]');
  console.log(json(await assemble(options)).trim());
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    console.error(`Runtime source handoff failed: ${error.message}`);
    process.exitCode = 1;
  });
}
