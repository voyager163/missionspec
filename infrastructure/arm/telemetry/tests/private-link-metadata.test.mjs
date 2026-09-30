import assert from 'node:assert/strict';
import test from 'node:test';
import { privateLinkGeneration, privateLinkResourceState } from '../private-link-readback.mjs';
import { queueArmInstant } from '../queue-adoption.mjs';

function registry(createdAt) {
  return {
    id: '/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/missionspec-unit-telemetry/providers/Microsoft.ContainerRegistry/registries/unitregistry',
    type: 'Microsoft.ContainerRegistry/registries',
    systemData: { createdAt, lastModifiedAt: createdAt, createdByType: 'Application' },
    properties: {},
  };
}

test('explicit zero-offset provider metadata retains raw bytes and exact 100ns creation identity', () => {
  const value = '2026-09-23T03:52:56.5359041+00:00', original = registry(value), saved = structuredClone(original);
  assert.deepEqual(privateLinkGeneration(original), privateLinkGeneration(registry('2026-09-23T03:52:56.5359041Z')));
  assert.equal(privateLinkGeneration(original).createdAt, queueArmInstant('2026-09-23T03:52:56.5359041Z').toString());
  assert.equal(privateLinkResourceState(original).systemData.createdAt, value);
  assert.deepEqual(original, saved);
  assert.notEqual(privateLinkGeneration(original).createdAt,
    privateLinkGeneration(registry('2026-09-23T03:52:56.5359042+00:00')).createdAt);
});

test('metadata UTC support cannot invent a timezone or admit malformed and unknown offsets', () => {
  for (const value of [
    '2026-09-23T03:52:56.5359041', '2026-09-23T03:52:56.5359041+01:00',
    '2026-09-23T03:52:56.5359041-00:00', '2026-09-23T03:52:56.53590410+00:00',
    '2026-02-30T03:52:56.5359041+00:00', '2026-09-23T03:52:56.5359041Z+00:00', null,
  ]) assert.throws(() => privateLinkGeneration(registry(value)), /QUEUE_ADOPTION_ARM_TIME_INVALID/);
  assert.throws(() => queueArmInstant('2026-09-23T03:52:56.5359041+00:00'), /QUEUE_ADOPTION_ARM_TIME_INVALID/);
});
