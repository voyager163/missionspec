import { buildPhase, digest, ids, json, SYNTHETIC_FIXTURES, TOGGLE_PHASES } from '../definition.mjs';
import { resourceContext, verifyWindowPredecessor } from '../policy.mjs';
import { buildSyntheticWindow } from '../controller.mjs';

// Closed inert predecessor evidence for exercising the real upgrade IO adapter.
export function terminalReceiverWindow(c, prerequisites, origin, source, at) {
  const r = ids(c), iso = offset => new Date(at + offset).toISOString();
  const instance = { version: 1, id: '00000000-0000-4000-8000-000000000099',
    predecessorSha256: digest('earlier inert window'), previousInstanceIds: [] };
  const phases = Object.fromEntries(TOGGLE_PHASES.map(name => [name, buildPhase(c, name, null, prerequisites, undefined, undefined, instance)]));
  const anchor = prerequisites['disabled-app'].resources[r.app];
  const whatifs = {
    'synthetic-admission': { status: 'Succeeded', changes: [{ resourceId: r.app, changeType: 'Modify',
      before: anchor, after: { ...structuredClone(phases['synthetic-admission'].resources[0].expected), id: r.app } }] },
    'synthetic-disable': { status: 'Succeeded', changes: [{ resourceId: r.app, changeType: 'NoChange' }] },
  };
  const window = buildSyntheticWindow(c, phases, prerequisites, origin, source, whatifs);
  const approvals = {}, journals = {}, receipts = {}, deployments = {};
  for (const [i, name] of TOGGLE_PHASES.entries()) {
    const phase = phases[name], app = structuredClone(anchor);
    app.properties = { ...app.properties, ...structuredClone(phase.resources[0].expected.properties) };
    app.properties.configuration.ingress.fqdn = anchor.properties.configuration.ingress.fqdn;
    Object.assign(app.properties, { latestRevisionName: `missionspec-test-ingest--prior-${i}`,
      latestReadyRevisionName: `missionspec-test-ingest--prior-${i}`, runningStatus: 'Running', provisioningState: 'Succeeded' });
    deployments[name] = { id: phase.deploymentId, properties: { mode: 'Incremental', provisioningState: 'Succeeded',
      correlationId: `prior-${i}`, timestamp: iso(i * 1000 + 100), templateHash: digest(json(phase.template)) } };
    approvals[name] = { version: 2, action: `synthetic-window-${name}`, windowInstanceId: instance.id, predecessorSha256: instance.predecessorSha256,
      windowSha256: digest(json(window)), phaseSha256: digest(json(phase)), configSha256: digest(json(c)),
      sourceSha256: source, originSha256: window.originSha256, receiptsSha256: window.receiptsSha256,
      baselineSha256: window.baselineSha256, reviewedWhatIfSha256: window.phases[name].reviewedWhatIfSha256,
      transitionSha256: window.phases[name].transitionSha256, approvedAt: iso(-60000), expiresAt: iso(1000000) };
    const revisionReadback = { value: [{ id: `${r.app}/revisions/${app.properties.latestRevisionName}`, name: app.properties.latestRevisionName,
      properties: { active: true, provisioningState: 'Provisioned', runningState: 'Running', healthState: 'Healthy',
        replicas: 1, trafficWeight: 100, template: structuredClone(app.properties.template) } }] };
    receipts[name] = { qualified: true, qualificationKind: 'ready-toggle-deployment', noCloudWrite: false, phase: name,
      configSha256: digest(json(c)), phaseSha256: digest(json(phase)), sourceSha256: source, windowSha256: digest(json(window)),
      approvalSha256: digest(json(approvals[name])), deployment: deployments[name], resources: { [r.app]: app },
      revisionReadback, completedAt: iso(i * 1000 + 100) };
    journals[name] = { phase: name, phaseSha256: digest(json(phase)), windowSha256: digest(json(window)),
      approvalSha256: digest(json(approvals[name])), outcome: 'readback-qualified', transportDispatchAttempted: true,
      receiptSha256: digest(json(receipts[name])), intentAt: iso(i * 1000) };
  }
  const last = receipts['synthetic-disable'];
  const run = { outcome: 'stopped-disabled', stage: 'finished', windowSha256: digest(json(window)),
    terminalFalseVerified: true, terminalDisabled503Verified: true, disableFailureCode: null,
    disableReceiptSha256: digest(json(last)), completedAt: iso(2000), deadlines: { terminalFalseAt: at + 1100 },
    failureCode: 'TOTAL_TIMEOUT', queries: [], healthGets: 0, enabledPosts: 1, disabledPosts: 1,
    requests: [
      { stage: 'two-fixed-events', method: 'POST', path: '/v1/events', fixture: SYNTHETIC_FIXTURES[0],
        response: { status: null, errorCode: 'TOTAL_TIMEOUT_1000MS', bodyBytes: 0, tlsVerified: true, durationMs: 1001 } },
      { stage: 'terminal-disabled-http', method: 'POST', path: '/v1/events',
        response: { status: 503, errorCode: null, bodyBytes: 0, tlsVerified: true, durationMs: 20, headerPolicy: { noStore: true } } },
    ] };
  const predecessor = { version: 1, kind: 'terminal-disabled-window', publication: { commitSha: 'a'.repeat(40), sourceSha256: source },
    window, phases, approvals, journals, receipts, prerequisiteReceipts: prerequisites, run,
    readback: { checkedAt: iso(3000), sourceSha256: source, deployments, app: last.resources[r.app],
      identities: resourceContext(c, prerequisites).identities, revisions: last.revisionReadback,
      privacy: { diagnostics: { [r.app]: { value: [] } }, exports: { value: [] } } } };
  verifyWindowPredecessor(c, predecessor);
  return predecessor;
}
