import test from 'node:test';
import { nsgAdoptionFixture } from './private-link-nsg-adoption.fixture.mjs';
import { verifyNsgRuntimeCase } from './private-link-nsg-runtime.fixture.mjs';

test('NSG v3 resolves one identical environment attempt through real runtime, retirement and completion', async t => {
  await verifyNsgRuntimeCase(t, await nsgAdoptionFixture(() => {}, true));
});
