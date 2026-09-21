import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const root = new URL('../../../../', import.meta.url);
const read = path => readFile(new URL(path, root), 'utf8');
const main = await read('infrastructure/opentofu/telemetry/main.tf');
const app = await read('infrastructure/opentofu/telemetry/app.tf');
const versions = await read('infrastructure/opentofu/telemetry/versions.tf');
const variables = await read('infrastructure/opentofu/telemetry/variables.tf');

test('static policy: canonical schema, generated copy, provenance, and storage columns agree', async () => {
  const source = await read('assets/schemas/telemetry-event.schema.json');
  assert.equal(await read('services/telemetry-ingest/schema/telemetry-event.schema.json'), source);
  const provenance = JSON.parse(await read('services/telemetry-ingest/schema/provenance.json'));
  assert.equal(provenance.sha256, createHash('sha256').update(source).digest('hex'));
  const columns = JSON.parse(await read('services/telemetry-ingest/schema/storage-columns.json'));
  assert.deepEqual(columns.map(column => column.name).sort(), ['TimeGenerated', ...Object.keys(JSON.parse(source).properties)].sort());
  assert.deepEqual(columns.find(column => column.name === 'TimeGenerated'), { name: 'TimeGenerated', type: 'datetime' });
  assert.match(main, /jsondecode\(file\("\$\{path\.module\}\/\.\.\/\.\.\/\.\.\/services\/telemetry-ingest\/schema\/storage-columns\.json"\)\)/);
});

test('static policy: 180-day Analytics and total retention, no export/archive or diagnostic routing', () => {
  assert.match(main, /retention_in_days\s*=\s*180/);
  assert.match(main, /plan\s*=\s*"Analytics"/);
  assert.match(main, /retentionInDays\s*=\s*180/);
  assert.match(main, /totalRetentionInDays\s*=\s*180/);
  assert.match(main, /logs_destination\s*=\s*null/);
  assert.match(main, /local_authentication_enabled\s*=\s*false/);
  assert.doesNotMatch(main + app, /resource\s+"[^"]*(diagnostic|data_export|data_collection_endpoint|application_insights)/);
  assert.doesNotMatch(app, /APPLICATIONINSIGHTS|APPINSIGHTS|OTEL_|AZURE_LOG_LEVEL/);
});

test('static policy: direct DCR, narrow upload role, separate private-pull identity, scoped queries', () => {
  assert.match(main, /kind\s*=\s*"Direct"/);
  assert.match(main, /data_actions\s*=\s*\["Microsoft\.Insights\/Telemetry\/Write"\]/);
  assert.match(main, /scope\s*=\s*azapi_resource\.dcr\.id/);
  assert.match(main, /role_definition_name\s*=\s*"Log Analytics Reader"/);
  assert.match(main, /scope\s*=\s*azurerm_log_analytics_workspace\.telemetry\.id/);
  assert.match(app, /identity\s*=\s*azurerm_user_assigned_identity\.pull\.id/);
  assert.match(app, /AZURE_CLIENT_ID\s*=\s*azurerm_user_assigned_identity\.ingest\.client_id/);
  assert.match(main, /admin_enabled\s*=\s*false/);
  assert.match(main, /anonymous_pull_enabled\s*=\s*false/);
});

test('static policy: TLS, digest-only image, explicit singleton/cost policy and private state prerequisite', () => {
  assert.match(app, /allow_insecure_connections\s*=\s*false/);
  assert.match(app, /revision_mode\s*=\s*"Single"/);
  assert.match(app, /telemetry-ingest@\$\{/);
  assert.doesNotMatch(app, /:latest/);
  assert.match(variables, /var\.scaling\.max_replicas\s*==\s*1/);
  assert.match(variables, /var\.cost_policy\.reviewed/);
  assert.match(versions, /backend\s+"azurerm"\s*\{\s*use_azuread_auth\s*=\s*true\s*\}/);
  assert.match(versions, /version\s*=\s*"= 5\.6\.0"/);
  assert.match(versions, /version\s*=\s*"= 2\.12\.0"/);
  assert.doesNotMatch(main + app + versions, /client_secret|access_key|sas_token|provisioner\s+"/);
});
