// Actual 2026-09-24 FullResourcePayloads shape, with only collector identifiers anonymized.
// Requested properties omitted by ARM remain absent. This is UNIT evidence, not a cloud receipt.
export function capturedQueueWhatIf(f) {
  const { c, r, topology: { ids: q } } = f;
  return { status: 'Succeeded', properties: { changes: [
    ...[r.app, r.environment, r.registry, r.dcr, r.ingestIdentity, r.pullIdentity, r.workspace]
      .map(resourceId => ({ resourceId, changeType: 'Ignore' })),
    { resourceId: q.account, changeType: 'Create', after: {
      apiVersion: '2025-01-01', id: q.account, kind: 'StorageV2', location: 'australiaeast', name: q.accountName,
      properties: {
        allowBlobPublicAccess: false, allowCrossTenantReplication: false, allowSharedKeyAccess: false,
        defaultToOAuthAuthentication: true, encryption: { keySource: 'Microsoft.Storage' },
        isHnsEnabled: false, isLocalUserEnabled: false, isSftpEnabled: false, minimumTlsVersion: 'TLS1_2',
        networkAcls: { bypass: 'None', defaultAction: 'Allow' }, publicNetworkAccess: 'Enabled', supportsHttpsTrafficOnly: true,
      }, sku: { name: 'Standard_LRS' },
      tags: { collectorRun: c.runId, product: 'MissionSpec', purpose: 'aggregate-telemetry' },
      type: 'Microsoft.Storage/storageAccounts',
    } },
    { resourceId: q.service, changeType: 'Create', after: {
      apiVersion: '2025-01-01', id: q.service, name: 'default', type: 'Microsoft.Storage/storageAccounts/queueServices',
    } },
    { resourceId: q.queue, changeType: 'Create', after: {
      apiVersion: '2025-01-01', id: q.queue, name: 'telemetry-events-v1', type: 'Microsoft.Storage/storageAccounts/queueServices/queues',
    } },
  ] } };
}
