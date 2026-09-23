// Offline container check. The optional TLS directory contains a generated localhost-only test certificate.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, createReadStream } from 'node:fs';
import { readFile, readdir, stat } from 'node:fs/promises';
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer, get as httpsGet } from 'node:https';
import { rootCertificates } from 'node:tls';
import { pathToFileURL } from 'node:url';

const directory = '/usr/share/doc/telemetry-runtime';
const manifestBytes = await readFile(`${directory}/runtime-source-manifest.json`);
const manifest = JSON.parse(manifestBytes);
const receipt = JSON.parse(await readFile(`${directory}/runtime-source-receipt.json`));
assert.equal(process.platform, 'linux');
assert.equal(process.arch, 'x64');
assert.equal(process.getuid(), 65532);
assert.equal(process.version, `v${manifest.node.version}`);
assert.equal(createHash('sha256').update(manifestBytes).digest('hex'), receipt.manifestSha256);
assert.equal((await stat(`${directory}/${receipt.filename}`)).size, receipt.size);
const archiveHash = createHash('sha256');
for await (const chunk of createReadStream(`${directory}/${receipt.filename}`)) archiveHash.update(chunk);
assert.equal(archiveHash.digest('hex'), receipt.sha256);
for (const absent of [
  '/bin/sh', '/bin/bash', '/usr/bin/sh', '/usr/bin/bash', '/usr/bin/perl', '/usr/bin/gzip',
  '/usr/bin/mount', '/usr/bin/apt', '/usr/bin/dpkg', '/usr/local/bin/npm',
  '/usr/local/bin/corepack', '/usr/local/bin/yarn', '/usr/local/lib/node_modules/npm',
  '/usr/local/lib/node_modules/corepack', '/opt/yarn-v1.22.22',
]) assert.equal(existsSync(absent), false, `Unused executable/toolchain still present: ${absent}`);
const packages = (await readdir('/var/lib/dpkg/status.d')).filter(name => !name.endsWith('.md5sums')).sort();
assert.deepEqual(packages, manifest.packages.map(entry => entry.name).sort());
for (const entry of manifest.packages) {
  const file = manifest.files.find(item => item.path === entry.metadataPath);
  assert(file);
  assert.equal(createHash('sha256').update(await readFile(`/${entry.metadataPath.slice('runtime/'.length)}`)).digest('hex'), file.sha256);
  assert(existsSync(`${directory}/runtime-notices/${entry.copyrightPath}`));
}
const nodeHash = createHash('sha256');
for await (const chunk of createReadStream(process.execPath)) nodeHash.update(chunk);
assert.equal(nodeHash.digest('hex'), manifest.node.binarySha256);
assert(rootCertificates.length > 50);
assert.match(await readFile('/etc/ssl/certs/ca-certificates.crt', 'utf8'), /BEGIN CERTIFICATE/u);
assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, undefined);
assert.equal(process.env.NODE_EXTRA_CA_CERTS, undefined);
assert(process.execArgv.includes('--disable-sigusr1'));
assert(process.execArgv.includes('--no-turbofan'));
assert(process.execArgv.includes('--no-maglev'));
const inspector = await import('node:inspector');
assert.equal(inspector.url(), undefined);

const { ManagedIdentityCredential } = await import('@azure/identity');
const { AzureLogger, setLogLevel } = await import('@azure/logger');
setLogLevel(undefined);
AzureLogger.log = () => {};
const clientId = '00000000-0000-4000-8000-000000000001';
const platformEnvironment = ['IDENTITY_ENDPOINT', 'IDENTITY_HEADER'];
assert(platformEnvironment.every(key => process.env[key] === undefined));
const observations = [];
const identity = httpServer((request, response) => {
  observations.push({ url: request.url, header: request.headers['x-identity-header'] });
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(JSON.stringify({
    access_token: 'offline-test-token-not-a-credential', expires_on: String(Math.floor(Date.now() / 1000) + 3600),
    resource: 'https://monitor.azure.com', token_type: 'Bearer',
  }));
});
try {
  identity.listen(0, '127.0.0.1');
  await once(identity, 'listening');
  process.env.IDENTITY_ENDPOINT = `http://127.0.0.1:${identity.address().port}/identity`;
  process.env.IDENTITY_HEADER = 'offline-test-header';
  const credential = new ManagedIdentityCredential({
    clientId, retryOptions: { maxRetries: 0 },
  });
  const token = await credential.getToken('https://monitor.azure.com/.default');
  assert.equal(token.token, 'offline-test-token-not-a-credential');
  assert.equal(observations.length, 1);
  const request = new URL(observations[0].url, process.env.IDENTITY_ENDPOINT);
  assert.equal(request.searchParams.get('client_id'), clientId);
  assert.equal(request.searchParams.get('resource'), 'https://monitor.azure.com');
  assert.equal(observations[0].header, 'offline-test-header');
} finally {
  for (const key of platformEnvironment) delete process.env[key];
  identity.closeAllConnections();
  await new Promise(resolve => identity.close(resolve));
}

const tlsDirectory = process.env.MSR_TEST_TLS_DIR;
assert(tlsDirectory, 'Supply an explicit generated localhost-only TLS fixture directory.');
const cert = await readFile(`${tlsDirectory}/localhost.crt`);
const key = await readFile(`${tlsDirectory}/localhost.key`);
const tls = httpsServer({ cert, key }, (_request, response) => { response.writeHead(204); response.end(); });
const requestTls = ca => new Promise((resolve, reject) => {
  const request = httpsGet({
    host: '127.0.0.1', port: tls.address().port, servername: 'localhost',
    rejectUnauthorized: true, ...(ca === undefined ? {} : { ca }),
  }, response => { response.resume(); response.once('end', () => resolve(response.statusCode)); });
  request.once('error', reject);
});
try {
  tls.listen(0, '127.0.0.1');
  await once(tls, 'listening');
  assert.equal(await requestTls(cert), 204);
  await assert.rejects(requestTls(undefined), error => error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT');
} finally {
  tls.closeAllConnections();
  await new Promise(resolve => tls.close(resolve));
}
const { createTelemetryServer } = await import(pathToFileURL(`${process.cwd()}/dist/server.js`));
assert.equal(typeof createTelemetryServer, 'function');
console.log(JSON.stringify({
  result: 'CONTAINER_RUNTIME_COMPATIBILITY_PASSED', platform: `${process.platform}/${process.arch}`,
  uid: process.getuid(), packages: packages.length, node: process.version,
  sourceArchiveSha256: receipt.sha256, sourceArchiveBytes: receipt.size,
  managedIdentity: 'loopback-fixture-passed', tls: 'verified-localhost-and-rejected-untrusted',
  nativeVulnerabilityCoverage: 'partial-see-separate-advisory-review', productionAzureQualification: false,
}));
