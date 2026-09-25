import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import mutableFs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync, gunzipSync } from 'node:zlib';
import test from 'node:test';
import {
  acquireArtifact, assemble, inspectTarGzip, packageFromStatus, safePath,
  serviceSnapshot, validateLock, validateUrl, verifyDsc, verifyFile, verifyUpstream, writeArchive,
} from '../scripts/runtime-sources.mjs';

const service = fileURLToPath(new URL('../', import.meta.url));
const real = JSON.parse(await fs.readFile(path.join(service, 'runtime-sources.lock.json')));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const clone = () => structuredClone(real);
const entry = (name, bytes) => ({ path: name, bytes, size: bytes.length, sha256: hash(bytes) });
async function scratch(t) {
  const root = path.join(process.cwd(), `.runtime-sources-test-${randomUUID()}`);
  await fs.mkdir(root);
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}
function tarGzip(files) {
  const chunks = [];
  for (const [name, value] of Object.entries(files)) {
    const bytes = Buffer.from(value), header = Buffer.alloc(512);
    header.write(name, 0, 100);
    for (const [offset, length, number] of [[100, 8, 0o644], [108, 8, 0], [116, 8, 0], [124, 12, bytes.length], [136, 12, 0]]) {
      header.write(`${number.toString(8).padStart(length - 1, '0')}\0`, offset, length);
    }
    header.fill(32, 148, 156); header.write('0', 156);
    header.write('ustar\0', 257); header.write('00', 263);
    header.write(`${header.reduce((a, b) => a + b, 0).toString(8).padStart(6, '0')}\0 `, 148);
    chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]));
}
async function fixture(root) {
  const lock = clone(), cache = path.join(root, 'cache'), projectRoot = path.join(root, 'project');
  await fs.mkdir(cache); await fs.mkdir(projectRoot);
  lock.packages = lock.packages.slice(0, 1); lock.sources = lock.sources.slice(0, 1);
  const source = lock.sources[0], n = lock.node, d = lock.distroless;
  const binary = Buffer.from('offline fixture Node executable identity');
  const license = Buffer.from('offline fixture license');
  const sourceBytes = Buffer.from('offline complete native source fixture');
  const dsc = Buffer.from(`Format: 3.0 (native)\nSource: ${source.name}\nVersion: ${source.version}\nChecksums-Sha256:\n ${hash(sourceBytes)} ${sourceBytes.length} ${source.artifacts[1]}\n`);
  const data = new Map([
    [source.dsc, dsc], [source.artifacts[1], sourceBytes],
    [n.sourceArtifact, tarGzip({ [`node-v${n.version}/LICENSE`]: license })],
    [n.distributionArtifact, tarGzip({ [`node-v${n.version}-linux-x64/bin/node`]: binary, [`node-v${n.version}-linux-x64/LICENSE`]: license })],
    [n.signatureArtifact, Buffer.from('offline unverified signature fixture')],
    [d.sourceArtifact, tarGzip({ [`distroless-${d.revision}/LICENSE`]: license })],
    [d.licenseArtifact, license],
  ]);
  data.set(n.shasumsArtifact, Buffer.from(`${hash(data.get(n.sourceArtifact))}  ${n.sourceArtifact}\n${hash(data.get(n.distributionArtifact))}  ${n.distributionArtifact}\n`));
  lock.artifacts = lock.artifacts.filter(a => data.has(a.filename)).map(a => ({ ...a, size: data.get(a.filename).length, sha256: hash(data.get(a.filename)) }));
  n.binarySha256 = hash(binary); n.binarySize = binary.length; n.licenseSha256 = hash(license);
  lock.files = lock.files.filter(f => !f.path.startsWith('runtime/var/lib/dpkg/status.d/') || f.path === lock.packages[0].metadataPath);
  const nodeLicense = lock.files.find(f => f.path === n.licensePath);
  nodeLicense.sha256 = hash(license); nodeLicense.size = license.length;
  lock.blobs[hash(license)] = license.toString('base64');
  lock.blobs = Object.fromEntries(lock.files.map(f => [f.sha256, lock.blobs[f.sha256]]));
  for (const [name, bytes] of data) await fs.writeFile(path.join(cache, name), bytes);
  const snapshotFiles = [
    'LICENSE', '.dockerignore', 'assets/schemas/telemetry-event.schema.json',
    'scripts/check-licenses.mjs', 'licenses/reviewed-texts.json', 'licenses/telemetry-runtime.json', 'licenses/TELEMETRY_THIRD_PARTY_NOTICES',
    'licenses/external-service-licenses.json', 'licenses/external/nodable-entities-2.1.0/LICENSE.md',
    ...['Dockerfile', 'package.json', 'package-lock.json', 'tsconfig.json', 'scripts/schema.mjs', 'scripts/runtime-sources.mjs',
      'scripts/container-smoke.mjs', 'scripts/container-qualification.mjs',
      'src/main.ts', 'schema/provenance.json', 'tests/runtime-sources.test.mjs'].map(f => `services/telemetry-ingest/${f}`),
  ];
  for (const name of snapshotFiles) {
    await fs.mkdir(path.dirname(path.join(projectRoot, name)), { recursive: true });
    await fs.writeFile(path.join(projectRoot, name), `offline fixture ${name}\n`);
  }
  await fs.writeFile(path.join(projectRoot, 'services/telemetry-ingest/Dockerfile'),
    `FROM ${lock.identities.nodeBuildBase} AS build\nFROM ${lock.identities.runtimeBase}\n`);
  const lockPath = path.join(root, 'lock.json');
  await fs.writeFile(lockPath, JSON.stringify(lock));
  return { lock, cache, projectRoot, lockPath, output: path.join(root, 'output'), data };
}

test('real lock closes the actual 14-package Debian 13 runtime, not the old builder', () => {
  validateLock(real);
  assert.equal(real.packages.length, 14);
  assert.equal(real.sources.length, 10);
  assert.equal(real.artifacts.filter(a => a.role === 'debian-source').length, 28);
  assert.equal(real.packages.find(p => p.name === 'zlib1g').sourceVersion, '1:1.3.dfsg+really1.3.1-1');
  assert.equal(real.sources.filter(s => s.name === 'gcc-14').length, 1);
  assert.equal(real.packages.filter(p => p.source === 'gcc-14').length, 4);
  assert.ok(!real.packages.some(p => /npm|corepack|yarn|bash|dpkg|apt/.test(p.name)));
});

test('control parsing preserves explicit source revisions, epochs and GCC binary/source differences', () => {
  assert.deepEqual(packageFromStatus('Package: libgcc-s1\nVersion: 14.2.0-19+b1\nArchitecture: amd64\nSource: gcc-14 (14.2.0-19)\n'), {
    name: 'libgcc-s1', version: '14.2.0-19+b1', architecture: 'amd64', source: 'gcc-14', sourceVersion: '14.2.0-19',
  });
  assert.equal(packageFromStatus('Package: zlib1g\nVersion: 1:1.3-1+b1\nSource: zlib (1:1.3-1)\n').sourceVersion, '1:1.3-1');
});

test('closed lock rejects unknown fields, missing metadata, notices, source versions and surplus sources', () => {
  const mutations = [
    l => { l.extra = true; },
    l => { l.artifacts[0].credentials = 'not-allowed'; },
    l => { l.artifacts[0].sha256 = 'bad'; },
    l => { l.artifacts[0].size = 0; },
    l => { l.packages[0].sourceVersion = 'wrong'; },
    l => { l.sources.pop(); },
    l => { l.packages.pop(); },
    l => { l.packages.push(l.packages[0]); },
    l => { l.files = l.files.filter(f => f.path !== l.packages[0].copyrightPath); },
    l => { l.artifacts.push({ ...l.artifacts[0], filename: 'extra-source.tar.gz' }); },
    l => { l.blobs['a'.repeat(64)] = 'Zm9v'; },
    l => { l.identities.runtimeBase = 'gcr.io/distroless/cc-debian13:nonroot'; },
    l => { l.identities.runtimeBase = `gcr.io/distroless/cc-debian13:nonroot@sha256:${'a'.repeat(64)}`; },
  ];
  for (const mutate of mutations) {
    const l = clone(); mutate(l);
    assert.throws(() => validateLock(l));
  }
});

test('paths and source URLs reject traversal, mutable refs, credentials and non-public endpoints', () => {
  for (const value of ['../secret', '/root', 'a/../b', 'a\\b', 'a//b', 'a:\n', 'C:drive']) assert.throws(() => safePath(value));
  for (const value of [
    'http://nodejs.org/dist/v24.21.0/SHASUMS256.txt',
    'https://user:secret@nodejs.org/dist/v24.21.0/SHASUMS256.txt',
    'https://nodejs.org/dist/latest/SHASUMS256.txt',
    'https://nodejs.org/dist/v24.21.0/SHASUMS256.txt?token=secret',
    'https://localhost/source.tar.gz',
    'https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/LICENSE',
    'https://codeload.github.com/GoogleContainerTools/distroless/tar.gz/main',
  ]) assert.throws(() => validateUrl(value));
  assert.doesNotThrow(() => safePath('openssl_3.5.7-1~deb13u2.debian.tar.xz'));
  for (const a of real.artifacts) assert.doesNotThrow(() => validateUrl(a.url));
});

test('cache verification is offline by default and refuses corruption and symlinks', async t => {
  const root = await scratch(t), bytes = Buffer.from('verified');
  const a = { filename: 'source.dsc', url: 'https://snapshot.debian.org/file/' + 'a'.repeat(40), sha256: hash(bytes), size: bytes.length };
  let calls = 0;
  const noNetwork = () => { calls++; throw new Error('network forbidden'); };
  await assert.rejects(acquireArtifact(a, root, false, noNetwork), /use --download/);
  await fs.writeFile(path.join(root, a.filename), bytes);
  await acquireArtifact(a, root, false, noNetwork);
  await fs.writeFile(path.join(root, a.filename), 'tampered');
  await assert.rejects(acquireArtifact(a, root, true, noNetwork), /SHA256/);
  await fs.rm(path.join(root, a.filename));
  await fs.writeFile(path.join(root, 'target'), bytes);
  await fs.symlink('target', path.join(root, a.filename));
  await assert.rejects(verifyFile(path.join(root, a.filename), a), /type\/length/);
  assert.equal(calls, 0);
});

test('explicit download enforces byte bounds, digest, no redirects, and removes partial failures', async t => {
  const root = await scratch(t), bytes = Buffer.from('download fixture');
  const a = { filename: 'source.dsc', url: 'https://snapshot.debian.org/file/' + 'a'.repeat(40), sha256: hash(bytes), size: bytes.length };
  const mock = async (_url, options) => {
    assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit');
    return new Response(bytes, { headers: { 'content-length': String(bytes.length) } });
  };
  await acquireArtifact(a, root, true, mock);
  await verifyFile(path.join(root, a.filename), a);
  await fs.rm(path.join(root, a.filename));
  for (const response of [
    new Response(Buffer.alloc(bytes.length + 1)),
    new Response(Buffer.alloc(bytes.length)),
    new Response(bytes.subarray(1)),
    new Response(bytes, { headers: { 'content-length': '999' } }),
    new Response(null, { status: 302, headers: { location: 'https://example.com/' } }),
  ]) {
    await assert.rejects(acquireArtifact(a, root, true, async () => response));
    assert.deepEqual(await fs.readdir(root), []);
  }
});

test('DSC checksums enforce exact complete source component closure', async t => {
  const f = await fixture(await scratch(t)), source = f.lock.sources[0];
  const input = f.data.get(source.dsc).toString(), artifacts = validateLock(f.lock).artifacts;
  verifyDsc(source, input, artifacts);
  await verifyUpstream(f.lock, f.cache);
  for (const changed of [
    input.replace(`Version: ${source.version}`, 'Version: other'),
    input.replace(/Checksums-Sha256:[\s\S]*/, ''),
    input.replace(hash(f.data.get(source.artifacts[1])), 'a'.repeat(64)),
    `${input} ${'b'.repeat(64)} 123 missing.orig.tar.xz\n`,
    input.replace(source.artifacts[1], '../escape.tar.xz'),
  ]) assert.throws(() => verifyDsc(source, changed, artifacts));
});

test('upstream identity checks reject a mismatched Node binary and source license', async t => {
  const f = await fixture(await scratch(t));
  f.lock.node.binarySha256 = 'a'.repeat(64);
  await assert.rejects(verifyUpstream(f.lock, f.cache), /Node binary mismatch/);
  f.lock.node.binarySha256 = hash(Buffer.from('offline fixture Node executable identity'));
  const source = f.lock.artifacts.find(a => a.filename === f.lock.node.sourceArtifact);
  const corrupt = tarGzip({ [`node-v${f.lock.node.version}/LICENSE`]: 'wrong license' });
  source.size = corrupt.length; source.sha256 = hash(corrupt);
  await fs.writeFile(path.join(f.cache, source.filename), corrupt);
  await fs.writeFile(path.join(f.cache, f.lock.node.shasumsArtifact),
    `${source.sha256}  ${source.filename}\n${hash(f.data.get(f.lock.node.distributionArtifact))}  ${f.lock.node.distributionArtifact}\n`);
  await assert.rejects(verifyUpstream(f.lock, f.cache), /source license mismatch/);
});

test('ustar generation is deterministic with fixed timestamps and rejects changed inputs', async t => {
  const root = await scratch(t), entries = [entry('b', Buffer.alloc(65540, 42)), entry('a', Buffer.from('a'))];
  await writeArchive(path.join(root, 'one.gz'), entries);
  await writeArchive(path.join(root, 'two.gz'), entries.toReversed());
  const one = await fs.readFile(path.join(root, 'one.gz'));
  assert.deepEqual(one, await fs.readFile(path.join(root, 'two.gz')));
  assert.deepEqual(one.subarray(0, 10), Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255]));
  const tar = gunzipSync(one);
  assert.equal(tar.subarray(136, 147).toString(), '00000000000');
  assert.equal(tar.subarray(100, 107).toString(), '0000644');
  const inspected = await inspectTarGzip(path.join(root, 'one.gz'), { 'runtime-corresponding-source/a': { maxBytes: 1, capture: true } });
  assert.equal(inspected.get('runtime-corresponding-source/a').bytes.toString(), 'a');
  await assert.rejects(writeArchive(path.join(root, 'bad.gz'), [{ ...entries[0], sha256: 'a'.repeat(64) }]), /input changed/);
  await assert.rejects(writeArchive(path.join(root, 'duplicate.gz'), [entries[0], entries[0]]), /Duplicate/);
});

test('offline end-to-end assembly ships sources, manifest, notices and service snapshot, not distribution binaries', async t => {
  const f = await fixture(await scratch(t));
  const first = await assemble(f), second = await assemble({ ...f, output: `${f.output}-second` });
  assert.equal(first.sha256, second.sha256);
  assert.equal(first.manifestSha256, second.manifestSha256);
  const manifest = JSON.parse(await fs.readFile(path.join(f.output, 'runtime-source-manifest.json')));
  assert.equal(manifest.verification.signaturesAuthenticated, false);
  assert.ok(manifest.files.some(f => f.path.endsWith('/src/main.ts')));
  assert.ok(manifest.files.some(f => f.path.endsWith('/Dockerfile')));
  assert.ok(manifest.files.some(f => f.path === 'service/services/telemetry-ingest/runtime-sources.lock.json'));
  for (const file of ['licenses/external-service-licenses.json', 'licenses/external/nodable-entities-2.1.0/LICENSE.md']) {
    assert.ok(manifest.files.some(f => f.path === `service/${file}`));
  }
  assert.ok(!manifest.files.some(f => f.path.endsWith('linux-x64.tar.gz')));
  assert.ok(!manifest.files.some(f => f.path.includes('node_modules')));
  assert.match(await fs.readFile(path.join(f.output, 'runtime-notices/NOTICE'), 'utf8'), /not.*\n.*a future source offer/);
  await assert.rejects(assemble(f), /must not already exist/);
});

test('corresponding-source assembly requires the reviewed external service license inputs', async t => {
  for (const file of ['licenses/external-service-licenses.json', 'licenses/external/nodable-entities-2.1.0/LICENSE.md']) {
    const f = await fixture(await scratch(t));
    await fs.rm(path.join(f.projectRoot, file));
    await assert.rejects(assemble(f), /ENOENT/);
    await assert.rejects(fs.stat(f.output), /ENOENT/);
  }
});

test('source snapshots fail closed on missing build scripts and private/symlink additions', async t => {
  const f = await fixture(await scratch(t)), src = path.join(f.projectRoot, 'services/telemetry-ingest/src');
  await fs.writeFile(path.join(src, '.env'), 'private');
  await assert.rejects(assemble(f), /Unexpected service source file/);
  await fs.rm(path.join(src, '.env'));
  await fs.symlink(path.join(f.projectRoot, 'LICENSE'), path.join(src, 'link.ts'));
  await assert.rejects(assemble(f), /Symlinks/);
  await fs.rm(path.join(src, 'link.ts'));
  await fs.writeFile(path.join(f.projectRoot, 'services/telemetry-ingest/Dockerfile'), 'FROM node:latest\n');
  await assert.rejects(assemble(f), /Dockerfile bases/);
  await fs.rm(path.join(f.projectRoot, 'services/telemetry-ingest/Dockerfile'));
  await assert.rejects(assemble(f), /ENOENT/);
  await assert.rejects(fs.stat(f.output), /ENOENT/);
});

test('source snapshots bind the opened file and parent identities before admitting bytes', async t => {
  for (const race of ['symlink-before-open', 'parent-before-open', 'replacement-during-read', 'growth-during-read']) {
    await t.test(race, async t => {
      const f = await fixture(await scratch(t));
      const file = path.join(f.projectRoot, 'LICENSE');
      const originalOpen = mutableFs.open;
      let armed = true;
      t.mock.method(mutableFs, 'open', async function (filename, ...args) {
        if (filename !== file || !armed) return originalOpen.call(this, filename, ...args);
        armed = false;
        if (race === 'symlink-before-open') {
          const outside = path.join(f.cache, 'unexpected');
          await fs.writeFile(outside, 'must not be included');
          await fs.unlink(file);
          await fs.symlink(outside, file);
        }
        if (race === 'parent-before-open') {
          await fs.rename(f.projectRoot, `${f.projectRoot}.retained`);
          await fs.mkdir(f.projectRoot);
          await fs.writeFile(file, 'replacement parent bytes');
        }
        const handle = await originalOpen.call(this, filename, ...args);
        if (race.endsWith('during-read')) {
          const read = handle.read.bind(handle);
          let first = true;
          handle.read = async (...input) => {
            if (first) {
              first = false;
              if (race === 'replacement-during-read') {
                await fs.rename(file, `${file}.retained`);
                await fs.writeFile(file, 'replacement pathname bytes');
              } else await fs.writeFile(file, Buffer.alloc(4 * 1024 * 1024 + 1, 65));
            }
            return read(...input);
          };
        }
        return handle;
      });
      await assert.rejects(serviceSnapshot(f.projectRoot),
        /type\/length|parent changed|pathname changed|file changed|bounded reader/);
      assert.equal(armed, false);
    });
  }
});

test('cached source artifacts cannot pass after pathname replacement during a held read', async t => {
  const root = await scratch(t), filename = path.join(root, 'artifact.tar.gz');
  const bytes = Buffer.from('reviewed source artifact');
  await fs.writeFile(filename, bytes);
  const originalOpen = mutableFs.open;
  let replaced = false;
  t.mock.method(mutableFs, 'open', async function (file, ...args) {
    const handle = await originalOpen.call(this, file, ...args);
    if (file !== filename) return handle;
    const read = handle.read.bind(handle);
    handle.read = async (...input) => {
      if (!replaced) {
        replaced = true;
        await fs.rename(filename, `${filename}.retained`);
        await fs.writeFile(filename, bytes);
      }
      return read(...input);
    };
    return handle;
  });
  await assert.rejects(verifyFile(filename, { size: bytes.length, sha256: hash(bytes) }), /file changed|parent changed/);
  assert.equal(replaced, true);
});
