// Execute from the packaged service working directory via stdin, with --network none.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

assert.notEqual(process.getuid(), 0);
assert.match(process.version, /^v24\./);
const { createTelemetryServer } = await import(pathToFileURL(`${process.cwd()}/dist/server.js`));
const schema = JSON.parse(await readFile('schema/telemetry-event.schema.json', 'utf8'));
const event = Object.fromEntries(Object.entries(schema.properties).map(([key, rule]) => [
  key, rule.const ?? rule.enum?.[0] ?? '0.0.0',
]));
const records = [];
const receiver = createTelemetryServer({
  enabled: true,
  storage: { async ingest(record) { records.push(record); } },
  limits: {
    bodyTimeoutMs: 200, storageTimeoutMs: 200, headersTimeoutMs: 200,
    maxConnections: 16, maxConcurrentRequests: 8, maxConcurrentIngestions: 4,
    requestsPerMinute: 100, eventsPerDay: 100,
  },
});
try {
  receiver.server.listen(0, '127.0.0.1');
  await once(receiver.server, 'listening');
  const origin = `http://127.0.0.1:${receiver.server.address().port}`;
  assert.equal((await fetch(`${origin}/health/live`)).status, 204);
  const response = await fetch(`${origin}/v1/events`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(event),
  });
  assert.equal(response.status, 204);
  assert.equal(await response.text(), '');
  assert.deepEqual(Object.keys(records[0]).sort(), [...Object.keys(schema.properties), 'TimeGenerated'].sort());
  process.stdout.write('CONTAINER_SMOKE_PASSED\n');
} finally {
  receiver.stop();
}
