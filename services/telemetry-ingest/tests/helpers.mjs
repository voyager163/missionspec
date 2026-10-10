import { request } from 'node:http';
import { once } from 'node:events';
import { createTelemetryServer } from '../dist/server.js';

export const event = {
  schemaVersion: 1, event: 'operation-completed', operation: 'draft',
  cliVersion: '0.0.0', outcome: 'completed', host: 'none', os: 'linux', durationBucket: null,
};
export const limits = {
  bodyTimeoutMs: 200, storageTimeoutMs: 200, headersTimeoutMs: 200,
  maxConnections: 16, maxConcurrentRequests: 8, maxConcurrentIngestions: 4,
  requestsPerMinute: 1000, eventsPerDay: 1000,
};

export async function start(t, options = {}) {
  const records = [];
  const receiver = createTelemetryServer({
    storage: { async ingest(record) { records.push(record); } },
    limits, enabled: true, ...options,
  });
  receiver.server.listen(0, '127.0.0.1');
  await once(receiver.server, 'listening');
  t.after(() => receiver.stop());
  return { ...receiver, records, port: receiver.server.address().port };
}

export function post(port, body = JSON.stringify(event), options = {}) {
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: '127.0.0.1', port, path: '/v1/events', method: 'POST',
      headers: { 'content-type': 'application/json' }, agent: false, ...options,
    }, res => {
      const chunks = [];
      res.on('data', data => chunks.push(data));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.once('error', reject);
    req.end(body);
  });
}

export function assertEmpty(assert, response, status) {
  assert.equal(response.status, status);
  assert.equal(response.body.length, 0);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['content-length'], '0');
}
