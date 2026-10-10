import assert from 'node:assert/strict';
import { digest, ids, json, ownerTags } from '../definition.mjs';
import { privateInput, privateLinkFixture, privateControlChain, privateControlHarness } from './private-link.fixture.mjs';
import { privateLinkNsgTarget, privateLinkNsgTargets, PRIVATE_LINK_NSG_AUTHORITY, privateLinkNsgAdoptionPins,
  observePrivateLinkNsgAdoption, adoptPrivateLinkNsg, withPrivateLinkNsgAdoption,
  PRIVATE_LINK_NSG_ATTACHED_MODE } from '../private-link-nsg-adoption.mjs';
const hash = value => digest(json(value)), clone = structuredClone;
const guid = n => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

// Entirely synthetic provenance and operator decisions; never retained Azure authority.
export async function nsgAdoptionFixture(trace = () => {}, attachedApps = false) {
  const f = await privateLinkFixture({ ...privateInput, version: 2 });
  trace('base');
  const evidence = await privateControlChain(f, 'create-queue-endpoint');
  trace('six-stage-prefix');
  const q = await privateControlHarness(f, evidence, 'create-environment');
  trace('checked-environment');
  q.io.write = async () => { throw new Error('PRIVATE_LINK_DISPATCH_GOVERNANCE_CHANGED'); };
  await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  const original = { phase: q.phase, publication: q.io.publication, approval: q.approval, preflight: q.proof,
    journal: clone(q.journal), intent: q.intent };
  const n = f.context.plan.topology.ids, t = privateLinkNsgTarget(f.c, f.context), r = ids(f.c);
  const actor = { appId: guid(701), homeTenantId: guid(702), homeObjectId: guid(703), localServicePrincipalId: guid(704),
    displayName: 'UNIT reviewed governance application' };
  let now = q.io.now() + 1000;
  const nsg = { id: t.id, name: t.name, type: 'Microsoft.Network/networkSecurityGroups', location: f.c.location,
    tags: ownerTags(f.c), etag: 'UNIT nsg etag', properties: { resourceGuid: guid(705), provisioningState: 'Succeeded',
      securityRules: [], subnets: [{ id: n.endpointSubnet }], defaultSecurityRules: [
        ['AllowVnetInBound', 65000, 'Allow', 'Inbound', 'VirtualNetwork', 'VirtualNetwork'],
        ['AllowAzureLoadBalancerInBound', 65001, 'Allow', 'Inbound', 'AzureLoadBalancer', '*'],
        ['DenyAllInBound', 65500, 'Deny', 'Inbound', '*', '*'],
        ['AllowVnetOutBound', 65000, 'Allow', 'Outbound', 'VirtualNetwork', 'VirtualNetwork'],
        ['AllowInternetOutBound', 65001, 'Allow', 'Outbound', '*', 'Internet'],
        ['DenyAllOutBound', 65500, 'Deny', 'Outbound', '*', '*'],
      ].map(([name, priority, access, direction, sourceAddressPrefix, destinationAddressPrefix]) => ({
        id: `${t.id}/defaultSecurityRules/${name}`, name, type: 'Microsoft.Network/networkSecurityGroups/defaultSecurityRules',
        etag: 'UNIT default-rule etag', properties: { description: 'UNIT native default rule', priority, access, direction,
          sourceAddressPrefix, destinationAddressPrefix, protocol: '*', provisioningState: 'Succeeded',
          sourcePortRange: '*', destinationPortRange: '*', sourceAddressPrefixes: [], destinationAddressPrefixes: [],
          sourcePortRanges: [], destinationPortRanges: [] },
      })) } };
  const other = privateLinkNsgTargets(f.c, f.context).unattachedApps;
  const unattachedNsg = clone(nsg);
  Object.assign(unattachedNsg, { id: other.id, name: other.name });
  unattachedNsg.properties.resourceGuid = guid(706); delete unattachedNsg.properties.subnets;
  for (const rule of unattachedNsg.properties.defaultSecurityRules) rule.id = `${other.id}/defaultSecurityRules/${rule.name}`;
  const current = clone(q.before);
  const attach = value => {
    if (value.id === n.endpointSubnet) value.properties.networkSecurityGroup = { id: t.id };
  };
  attach(current.resources[n.endpointSubnet]);
  current.resources[n.vnet].properties.subnets.forEach(attach);
  current.lists.subnets.value.forEach(attach);
  current.lists.addressSpaces.value.filter(value => value.id === n.vnet).forEach(v => v.properties.subnets.forEach(attach));
  current.lists.groupResources.value.push({ id: nsg.id, name: nsg.name, type: nsg.type, location: nsg.location, tags: nsg.tags });
  current.lists.groupResources.value.push({ id: unattachedNsg.id, name: unattachedNsg.name, type: unattachedNsg.type, location: unattachedNsg.location, tags: unattachedNsg.tags });
  const watcherId = `${r.sub}/resourceGroups/unit-observability/providers/Microsoft.Network/networkWatchers/unit-australiaeast`;
  const watchers = { value: [{ id: watcherId, name: 'unit-australiaeast', type: 'Microsoft.Network/networkWatchers',
    location: 'australiaeast', properties: { provisioningState: 'Succeeded' } }] };
  const snapshots = () => {
    const s = clone(current); s.version = 2; s.startedAt = s.completedAt = now;
    s.externalNsg = { version: 2, kind: 'observed-exact-private-link-governance-nsgs', startedAt: now, completedAt: now,
      nsg: clone(nsg), diagnostics: { value: [] }, unattachedNsg: clone(unattachedNsg), unattachedDiagnostics: { value: [] },
      watchers: clone(watchers), flowLogs: { [watcherId]: { value: [] } } };
    if (attachedApps) {
      Object.assign(s.externalNsg, { version: 3, attachmentMode: PRIVATE_LINK_NSG_ATTACHED_MODE,
        appsNsg: s.externalNsg.unattachedNsg, appsDiagnostics: s.externalNsg.unattachedDiagnostics });
      delete s.externalNsg.unattachedNsg; delete s.externalNsg.unattachedDiagnostics;
    }
    return s;
  };
  let eventId = 800;
  const activity = (target, operation, at, request, response) => ({ id: `${r.sub}/providers/Microsoft.Insights/eventtypes/management/values`,
    version: '2015-04-01', startedAt: new Date(now).toISOString(), completedAt: new Date(now).toISOString(),
    response: { value: ['Started', 'Accepted', 'Succeeded'].map((status, i) => ({
      eventDataId: guid(eventId++), eventTimestamp: new Date(at + i * 100).toISOString(),
      submissionTimestamp: new Date(at + i * 100 + 20).toISOString(), correlationId: guid(eventId + 20),
      resourceId: target, subscriptionId: f.c.subscriptionId, tenantId: actor.homeTenantId,
      operationName: { value: operation }, status: { value: status }, caller: actor.homeObjectId,
      claims: { appid: actor.appId, idtyp: 'app', iss: `https://sts.windows.net/${actor.homeTenantId}/`,
        'http://schemas.microsoft.com/identity/claims/objectidentifier': actor.homeObjectId,
        'http://schemas.microsoft.com/identity/claims/tenantid': actor.homeTenantId },
      authorization: { action: operation, scope: target },
      properties: i === 0 ? { requestbody: json(request) } : i === 1 ? { responseBody: json(response) } : {},
    })) } });
  const nsgActivity = activity(t.id, 'Microsoft.Network/networkSecurityGroups/write', now - 700,
    { properties: { securityRules: [] }, location: f.c.location, tags: '******' }, nsg);
  const unattachedNsgActivity = activity(other.id, 'Microsoft.Network/networkSecurityGroups/write', now - 700,
    { properties: { securityRules: [] }, location: f.c.location, tags: '******' }, unattachedNsg);
  for (const group of [nsgActivity, unattachedNsgActivity]) {
    const event = group.response.value.find(value => value.status.value === 'Accepted'), body = JSON.parse(event.properties.responseBody);
    for (const rule of body.properties.defaultSecurityRules) rule.properties.provisioningState = 'Updating';
    delete body.properties.subnets; event.properties.responseBody = json(body);
  }

  const vnetRequest = clone(current.resources[n.vnet]);
  vnetRequest.properties.subnets.find(value => value.id === n.endpointSubnet).properties.networkSecurityGroup.properties = { securityRules: [] };
  const vnetActivity = activity(n.vnet, 'Microsoft.Network/virtualNetworks/write', now - 300,
    vnetRequest, current.resources[n.vnet]);
  const priorRequest = clone(vnetRequest);
  delete priorRequest.properties.subnets.find(value => value.id === n.endpointSubnet).properties.networkSecurityGroup;
  priorRequest.properties.subnets.find(value => value.id === n.appsSubnet).properties.networkSecurityGroup = { id: other.id, properties: { securityRules: [] } };
  const priorResponse = clone(priorRequest);
  priorResponse.properties.subnets.find(value => value.id === n.appsSubnet).properties.networkSecurityGroup = { id: other.id };
  const priorVnetActivity = activity(n.vnet, 'Microsoft.Network/virtualNetworks/write', now - 450, priorRequest, priorResponse);
  const priorSuccess = priorVnetActivity.response.value.find(value => value.status.value === 'Succeeded');
  priorSuccess.eventTimestamp = new Date(now - 50).toISOString(); priorSuccess.submissionTimestamp = new Date(now - 30).toISOString();
  for (const group of [nsgActivity, unattachedNsgActivity, vnetActivity, priorVnetActivity]) for (const event of group.response.value) event.correlationId = group.response.value[0].correlationId;
  vnetActivity.response.value.push(...priorVnetActivity.response.value);
  const provenance = { version: 2, kind: 'exact-private-link-governance-nsgs-provenance', actor,
    writer: { appid: actor.appId, observedAt: new Date(now).toISOString(), response: {
      accountEnabled: true, appId: actor.appId, appOwnerOrganizationId: actor.homeTenantId,
      displayName: actor.displayName, id: actor.localServicePrincipalId, servicePrincipalType: 'Application' } },
    nsgActivity, unattachedNsgActivity, vnetActivity, subnetActivity: { ...clone(nsgActivity), response: { value: [] } } };
  if (attachedApps) {
    now += 1000;
    unattachedNsg.properties.subnets = [{ id: n.appsSubnet }];
    const attachApps = value => { if (value.id === n.appsSubnet) value.properties.networkSecurityGroup = { id: other.id }; };
    attachApps(current.resources[n.appsSubnet]);
    current.resources[n.vnet].properties.subnets.forEach(attachApps);
    current.lists.subnets.value.forEach(attachApps);
    current.lists.addressSpaces.value.filter(value => value.id === n.vnet).forEach(value => value.properties.subnets.forEach(attachApps));
    const request = clone(current.resources[n.vnet]);
    for (const subnet of request.properties.subnets) subnet.properties.networkSecurityGroup.properties = { securityRules: [] };
    const appsAttachmentActivity = activity(n.vnet, 'Microsoft.Network/virtualNetworks/write', now - 300, request, current.resources[n.vnet]);
    for (const event of appsAttachmentActivity.response.value) event.correlationId = appsAttachmentActivity.response.value[0].correlationId;
    Object.assign(provenance, { version: 3, attachmentMode: PRIVATE_LINK_NSG_ATTACHED_MODE, appsAttachmentActivity });
  }
  const read = q.io.read;
  let saved = null;
  const io = { ...q.io, now: () => now, account: async () => clone(current.accountContext),
    registry: async () => clone(current.images), verifyOriginal: async value => assert.deepEqual(value, original),
    read: async (request, deadline, paginated) => {
      if (request.id === t.id) return clone(nsg);
      if (request.id === other.id) return clone(unattachedNsg);
      if (request.id === t.id + '/providers/Microsoft.Insights/diagnosticSettings') return { value: [] };
      if (request.id === other.id + '/providers/Microsoft.Insights/diagnosticSettings') return { value: [] };
      if (request.id === `${r.sub}/providers/Microsoft.Network/networkWatchers`) return clone(watchers);
      if (request.id === watcherId + '/flowLogs') return { value: [] };
      if (request.id === original.phase.deploymentId) return null;
      q.setLive(current); return read(request, deadline, paginated);
    },
    saveAdoption: async record => { saved = clone(record); },
  };
  const proposal = await observePrivateLinkNsgAdoption(f.c, f.context, evidence, original, provenance, io);
  trace('observed-adoption');
  const userDecision = attachedApps ? 'UNIT adopt both existing corresponding NSG attachments with fresh validation; not real authority.'
    : 'UNIT preserve and explicitly adopt both exact governance NSGs in current states; not real authority.';
  const costDisclosure = { currency: 'USD', additionalFeeVerified: false, zeroFeeProven: false, unknownCostAccepted: true,
    budgetMutationAuthorized: false, evidence: 'UNIT disclosed unknown additional fee; no added logs or spend capability.' };
  costDisclosure.evidenceSha256 = digest(costDisclosure.evidence);
  const review = { ...(attachedApps ? { version: 3, attachmentMode: PRIVATE_LINK_NSG_ATTACHED_MODE } : { version: 2 }),
    action: attachedApps ? 'preserve-both-exact-private-link-nsg-attachments-readonly' : 'preserve-two-exact-private-link-governance-nsgs-readonly',
    proposalSha256: hash(proposal), sourceSha256: f.source, pins: privateLinkNsgAdoptionPins(f.c, f.context, proposal),
    userDecision, userDecisionSha256: digest(userDecision), costDisclosure,
    approvedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600000).toISOString() };
  const adoption = await adoptPrivateLinkNsg(f.c, f.context, evidence, proposal, review, io.publication, io);
  trace('adopted');
  const adoptedEvidence = withPrivateLinkNsgAdoption(f.c, f.context, evidence, adoption);
  trace('wrapped-evidence');
  assert.equal(saved.kind, 'reviewed-private-link-governance-nsg-adoption');
  return { f, evidence, adoptedEvidence, original, proposal, review, adoption, provenance, current: snapshots(),
    nsg, unattachedNsg, watchers, watcherId, io, snapshots, setNow: value => { now = value; }, authority: PRIVATE_LINK_NSG_AUTHORITY };
}

export function adoptedSnapshot(x, snapshot) {
  const n = x.f.context.plan.topology.ids;
  snapshot.version = 2; snapshot.externalNsg = clone(x.current.externalNsg);
  snapshot.externalNsg.startedAt = snapshot.externalNsg.completedAt = snapshot.startedAt;
  const attach = value => {
    if (value.id === n.endpointSubnet) value.properties.networkSecurityGroup = { id: x.nsg.id };
    if (x.adoption.version === 3 && value.id === n.appsSubnet) value.properties.networkSecurityGroup = { id: x.unattachedNsg.id };
  };
  attach(snapshot.resources[n.endpointSubnet]);
  attach(snapshot.resources[n.appsSubnet]);
  snapshot.resources[n.vnet].properties.subnets.forEach(attach);
  snapshot.lists.subnets.value.forEach(attach);
  snapshot.lists.addressSpaces.value.filter(value => value.id === n.vnet).forEach(value => value.properties.subnets.forEach(attach));
  for (const nsg of [x.nsg, x.unattachedNsg]) if (!snapshot.lists.groupResources.value.some(value => value.id === nsg.id)) {
    snapshot.lists.groupResources.value.push({ id: nsg.id, name: nsg.name, type: nsg.type, location: nsg.location, tags: nsg.tags });
  }
}
export function adoptedIO(x, io) {
  const read = io.read;
  io.read = async (request, deadline, paginated) => {
    for (const value of [x.nsg, x.unattachedNsg]) {
      if (request.id === value.id) return clone(value);
      if (request.id === `${value.id}/providers/Microsoft.Insights/diagnosticSettings`) return { value: [] };
    }
    if (request.id === `${ids(x.f.c).sub}/providers/Microsoft.Network/networkWatchers`) return clone(x.watchers);
    if (request.id === `${x.watcherId}/flowLogs`) return { value: [] };
    return read(request, deadline, paginated);
  };
}

export function retainedReadInvoke(f, snapshot, read, writer = null) {
  const manifests = new Map([[f.c.receiverDigest, snapshot.images.legacyManifest],
    [f.context.origin.receiver.candidate.profile.manifestDigest, snapshot.images.preparedManifest],
    [f.context.origin.queueProfile.manifestDigest, snapshot.images.queueManifest]]);
  return async args => {
    if (args[0] === 'ad') { assert(writer); return clone(writer); }
    if (args[0] === 'account') return clone(snapshot.accountContext);
    if (args[0] === 'acr') {
      if (args[1] === 'repository') return clone(snapshot.images.repositories);
      if (args[2] === 'list-metadata') return clone(snapshot.images.manifests);
      if (args[2] === 'list-referrers') return [];
      const manifest = args[args.indexOf('--name') + 1].split('@')[1];
      assert(manifests.has(manifest)); return clone(manifests.get(manifest));
    }
    assert.equal(args[0], 'rest'); assert.equal(args[args.indexOf('--method') + 1], 'GET');
    const url = new URL(args[args.indexOf('--url') + 1]), filter = new URLSearchParams(url.search);
    filter.delete('api-version');
    return read({ id: url.pathname, apiVersion: url.searchParams.get('api-version'), filter: filter.toString() || null }, Number.MAX_SAFE_INTEGER, true);
  };
}

export function retainedSourceLookup(...values) {
  const sources = new Map();
  const visit = value => {
    if (!value || typeof value !== 'object') return;
    if (typeof value.commitSha === 'string' && typeof value.sourceSha256 === 'string') {
      if (sources.has(value.commitSha)) assert.equal(sources.get(value.commitSha), value.sourceSha256);
      sources.set(value.commitSha, value.sourceSha256);
    }
    Object.values(value).forEach(visit);
  };
  values.forEach(visit);
  return async commit => { assert(sources.has(commit), 'UNIT unexpected policy publication'); return sources.get(commit); };
}
