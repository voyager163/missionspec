import { isDeepStrictEqual } from 'node:util';
import { closed, digest, fail, ids, json, ownerTags } from './definition.mjs';
import { verifyPrivateLinkEnvironmentWire, verifyPrivateLinkNameBinding, verifyPrivateLinkRuntimeName } from './private-link.mjs';

export const PRIVATE_LINK_WHATIF_STAGES = Object.freeze({
  'create-network': 4, 'create-queue-endpoint': 5, 'create-environment': 6,
  'create-queue-role': 11, 'assign-queue-role': 12, 'create-disabled-receiver': 14,
});
export const PRIVATE_LINK_RUNTIME_SUFFIXES = Object.freeze({
  'create-disabled': 'c', enable: 'e', disable: 'd', 'create-public-probe': 'p',
});

function staticTemplate(value) {
  if (typeof value === 'string' && /^\s*\[/u.test(value)) fail('STATIC_WHAT_IF_TEMPLATE_REQUIRED');
  if (Array.isArray(value)) value.forEach(staticTemplate);
  else if (value && typeof value === 'object') {
    if (Object.hasOwn(value, 'templateLink') || Object.hasOwn(value, 'parametersLink')) fail('INLINE_WHAT_IF_REQUIRED');
    Object.values(value).forEach(staticTemplate);
  }
}

/** This authorizes only a static, scope-bound what-if request, never the proposed mutation. */
export function privateLinkWhatIfContext(c, phase) {
  closed(phase, ['version', 'kind', 'phase', 'stage', 'planSha256', 'contextSha256', 'request', 'resources',
    'scope', 'deploymentId', 'template', 'rolloutMs', ...(phase.version === 2 ? ['wireProjection'] : [])]);
  if (!(phase.version === 1 || phase.version === 2 && phase.stage === 'create-environment') ||
      phase.kind !== 'fixed-private-link-control-phase' ||
      !Object.hasOwn(PRIVATE_LINK_WHATIF_STAGES, phase.stage) || phase.phase !== `private-link-${phase.stage}` ||
      !['planSha256', 'contextSha256'].every(key => /^[0-9a-f]{64}$/u.test(phase[key] ?? ''))) fail('FIXED_PRIVATE_LINK_WHATIF_REQUIRED');
  const r = ids(c), scope = phase.stage === 'create-queue-role' ? 'subscription' : 'group';
  const resourceScope = scope === 'subscription' ? r.sub : r.group;
  const prefix = `${resourceScope}/providers/Microsoft.Resources/deployments/${c.namePrefix}-pl-`;
  if (phase.scope !== resourceScope || typeof phase.deploymentId !== 'string' ||
      !phase.deploymentId.startsWith(prefix)) fail('FIXED_PRIVATE_LINK_WHATIF_REQUIRED');
  const tail = phase.deploymentId.slice(prefix.length);
  const match = /^([0-9a-f]{12})-(\d{1,2})$/u.exec(tail);
  if (!match || Number(match[2]) !== PRIVATE_LINK_WHATIF_STAGES[phase.stage] ||
      match[2] !== String(PRIVATE_LINK_WHATIF_STAGES[phase.stage])) fail('FIXED_PRIVATE_LINK_WHATIF_REQUIRED');
  closed(phase.request, ['method', 'id', 'apiVersion', 'body']);
  const requestBody = { ...(scope === 'subscription' ? { location: c.location } : {}),
    properties: { mode: 'Incremental', template: phase.template } };
  if (phase.request.method !== 'PUT' || phase.request.id !== phase.deploymentId ||
      phase.request.apiVersion !== '2022-09-01' || !isDeepStrictEqual(phase.request.body, requestBody) ||
      !Array.isArray(phase.resources) || phase.resources.length < 1 || phase.resources.length > 8 ||
      !isDeepStrictEqual(phase.template?.resources, phase.resources.map(value => value.expected))) fail('FIXED_PRIVATE_LINK_WHATIF_REQUIRED');
  if (phase.version === 2) {
    verifyPrivateLinkEnvironmentWire(phase);
    if (phase.resources[0].expected.name !== `${c.namePrefix}-private-environment`) fail('FIXED_PRIVATE_LINK_WHATIF_REQUIRED');
  }
  staticTemplate(phase.template);
  const body = JSON.stringify({ ...(scope === 'subscription' ? { location: c.location } : {}),
    properties: { mode: 'Incremental', parameters: {}, template: phase.template,
      whatIfSettings: { resultFormat: 'FullResourcePayloads' } } });
  const fields = { subscriptionId: c.subscriptionId, tenantId: c.tenantId, location: c.location,
    namePrefix: c.namePrefix, runId: c.runId, phase: phase.phase, scope, phaseSha256: digest(json(phase)),
    bodySha256: digest(body), windowInstanceId: null, predecessorSha256: null,
    migrationKey: match[1], migrationPlanSha256: phase.planSha256, migrationContextSha256: phase.contextSha256 };
  return { ...fields, contextSha256: digest(Object.values(fields).join('\n')), body };
}

export function privateLinkRuntimeWhatIfContext(c, phase) {
  closed(phase, ['version', 'kind', 'phase', 'action', 'windowInstanceId', 'predecessorSha256', 'targetSha256', 'request',
    ...(phase.version === 2 ? ['nameBinding'] : [])]);
  if (![1, 2].includes(phase.version) || phase.kind !== 'fixed-private-link-runtime-phase' ||
      !Object.hasOwn(PRIVATE_LINK_RUNTIME_SUFFIXES, phase.action) || phase.phase !== `private-link-runtime-${phase.action}` ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(phase.windowInstanceId ?? '') ||
      phase.windowInstanceId === c.runId ||
      !['predecessorSha256', 'targetSha256'].every(key => /^[0-9a-f]{64}$/u.test(phase[key] ?? ''))) {
    fail('FIXED_PRIVATE_LINK_RUNTIME_WHATIF_REQUIRED');
  }
  const r = ids(c);
  const name = `${c.namePrefix}-plr-${phase.windowInstanceId.replaceAll('-', '')}-${PRIVATE_LINK_RUNTIME_SUFFIXES[phase.action]}`;
  closed(phase.request, ['id', 'body']);
  closed(phase.request.body, ['properties']);
  closed(phase.request.body.properties, ['mode', 'template']);
  const template = phase.request.body.properties.template;
  closed(template, ['$schema', 'contentVersion', 'resources']);
  if (name.length > 64 || phase.request.id !== `${r.group}/providers/Microsoft.Resources/deployments/${name}` ||
      phase.request.body.properties.mode !== 'Incremental' ||
      template.$schema !== 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#' ||
      template.contentVersion !== '1.0.0.0' || !Array.isArray(template.resources) || template.resources.length !== 1) {
    fail('FIXED_PRIVATE_LINK_RUNTIME_WHATIF_REQUIRED');
  }
  const publicProbe = phase.action === 'create-public-probe';
  const projected = phase.version === 2 ? verifyPrivateLinkNameBinding(c, phase.nameBinding).projected : null;
  const expectedApp = projected ? projected[publicProbe ? 'publicProbe' : 'app'].split('/').at(-1) :
    `${c.namePrefix}-${publicProbe ? 'public-probe' : 'private-ingest'}`;
  verifyPrivateLinkRuntimeName(expectedApp);
  const expectedEnvironment = publicProbe ? r.environment
    : `${r.group}/providers/Microsoft.App/managedEnvironments/${c.namePrefix}-private-environment`;
  const app = template.resources[0], containers = app?.properties?.template?.containers;
  if (app?.type !== 'Microsoft.App/containerApps' || app.apiVersion !== '2025-07-01' ||
      app.name !== expectedApp || app.location !== c.location ||
      !isDeepStrictEqual(app.tags, ownerTags(c)) ||
      app.properties?.managedEnvironmentId !== expectedEnvironment ||
      !Array.isArray(containers) || containers.length !== 1 || !Array.isArray(containers[0].env) ||
      containers[0].env.filter(value => value.name === 'MSR_INGESTION_ENABLED').length !== 1 ||
      containers[0].env.find(value => value.name === 'MSR_INGESTION_ENABLED').value !== String(phase.action === 'enable')) {
    fail('FIXED_PRIVATE_LINK_RUNTIME_WHATIF_REQUIRED');
  }
  staticTemplate(template);
  const body = JSON.stringify({ properties: { mode: 'Incremental', parameters: {}, template,
    whatIfSettings: { resultFormat: 'FullResourcePayloads' } } });
  const fields = { subscriptionId: c.subscriptionId, tenantId: c.tenantId, location: c.location,
    namePrefix: c.namePrefix, runId: c.runId, phase: phase.phase, scope: 'group', phaseSha256: digest(json(phase)),
    bodySha256: digest(body), windowInstanceId: phase.windowInstanceId, predecessorSha256: phase.predecessorSha256,
    runtimeTargetSha256: phase.targetSha256 };
  return { ...fields, contextSha256: digest(Object.values(fields).join('\n')), body };
}
