import assert from 'node:assert/strict';
import test from 'node:test';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { CallToolRequestSchema, ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { requestMcpReview } from '../dist/mcp/confirmation.js';
import { digestContent, digestEffectScope, digestApprovalRequest } from '../dist/api/index.js';

const request = {
  contractVersion: 1, state: 'untrusted-request', purpose: 'artifact-edit', operation: 'principles',
  binding: {
    kind: 'project',
    workspace: { workspaceId: 'WSP-test', rootDigest: digestContent('TEST workspace') },
    revision: digestContent('TEST revision'), effects: digestEffectScope([]),
  },
  effects: [],
};

async function fixture(context, capabilities, action) {
  const server = new Server({ name: 'TEST-review-server', version: '0.0.0' }, { capabilities: { tools: {} } });
  const client = new Client({ name: 'NOT-an-identity', version: '0.0.0' }, { capabilities });
  const observations = [];
  if (action !== undefined) {
    client.setRequestHandler(ElicitRequestSchema, async (input) => {
      observations.push(input.params);
      return action;
    });
  }
  server.setRequestHandler(CallToolRequestSchema, async () => {
    const reviewed = await requestMcpReview(server, request, { summary: 'TEST ONLY synthetic review' });
    return { content: [{ type: 'text', text: JSON.stringify(reviewed) }] };
  });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left);
  await client.connect(right);
  context.after(async () => { await client.close(); await server.close(); });
  const review = async () => JSON.parse((await client.callTool({ name: 'TEST-review', arguments: { approved: true } })).content[0].text);
  return { review, observations };
}

test('tool arguments do not approve anything without negotiated user elicitation', async (context) => {
  const f = await fixture(context, {}, undefined);
  assert.deepEqual(await f.review(), { decision: 'unavailable', requestDigest: digestApprovalRequest(request) });
  assert.equal(f.observations.length, 0);
});

test('correlated form response binds exact displayed scope but issues no approval record', async (context) => {
  const f = await fixture(context, { elicitation: { form: {} } }, { action: 'accept', content: { decision: 'approve' } });
  const result = await f.review();
  assert.deepEqual(Object.keys(result).sort(), ['decision', 'requestDigest']);
  assert.equal(result.decision, 'accepted');
  assert.equal(result.requestDigest, digestApprovalRequest(request));
  assert(f.observations[0].message.includes(digestApprovalRequest(request)));
  assert.equal(f.observations[0].requestedSchema.properties.decision.default, 'decline');
});

test('decline/cancel and an accepted form without an approval choice remain non-authorizing', async (context) => {
  for (const action of [
    { action: 'decline' },
    { action: 'cancel' },
    { action: 'accept', content: { decision: 'decline' } },
  ]) {
    const f = await fixture(context, { elicitation: { form: {} } }, action);
    assert.notEqual((await f.review()).decision, 'accepted');
  }
});
