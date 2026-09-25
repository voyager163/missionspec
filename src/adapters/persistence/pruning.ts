import { digestApprovalRequest, parseApprovalReference, parseApprovalRequest, type ApprovalRequest } from '../../kernel/authority.js';
import { digestEffectScope } from '../../kernel/effects.js';
import { parseId, parseProjectPath } from '../../kernel/identifiers.js';
import { digestContent, parseDigest, parseWorkspaceBinding } from '../../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../../kernel/validation.js';
import type {
  EvidencePruneCompletion, EvidencePruneInventory, EvidencePruneObservation,
  EvidencePrunePlan, EvidencePrunePrepared, EvidencePruneTarget,
} from '../../ports/evidence-pruning.js';

function timestamp(value: unknown): string {
  const parsed = text(value, 'prune.timestamp', 24);
  if (!Number.isFinite(Date.parse(parsed)) || new Date(parsed).toISOString() !== parsed) {
    throw new ContractError('prune.timestamp', 'expected a canonical UTC timestamp');
  }
  return parsed;
}

export function parsePruneTarget(value: unknown): EvidencePruneTarget {
  const input = record(value, 'prune.target', ['id', 'runId', 'runRevision', 'evidenceDigest', 'path', 'rawDigest']);
  const id = parseId('evidence', input.id);
  const path = parseProjectPath(input.path);
  if (path !== `.missionspec/evidence/${id}.json`) {
    throw new ContractError('prune.path', 'only the exact immutable private evidence file may be removed');
  }
  return {
    id, runId: parseId('run', input.runId), runRevision: parseDigest(input.runRevision),
    evidenceDigest: parseDigest(input.evidenceDigest), path, rawDigest: parseDigest(input.rawDigest),
  };
}

export function makePruneInventory(value: Omit<EvidencePruneInventory, 'digest'>): EvidencePruneInventory {
  const input = record(value, 'prune.inventory', ['schemaVersion', 'workspace', 'items', 'acceptances']);
  if (input.schemaVersion !== 1) throw new ContractError('prune.inventory', 'unsupported version');
  const items = [...array(input.items, 'prune.items', parsePruneTarget, 1)].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  unique(items.map((item) => item.id), 'prune.items');
  unique(items.map((item) => item.path.toLowerCase()), 'prune.paths');
  const acceptances = [...array(input.acceptances, 'prune.acceptances', (entry) => {
    const item = record(entry, 'prune.acceptance', ['approval', 'revision', 'affectedEvidence']);
    const affectedEvidence = [...unique(array(item.affectedEvidence, 'prune.acceptance.evidence', (id) =>
      parseId('evidence', id), 1), 'prune.acceptance.evidence')].sort();
    if (affectedEvidence.some((id) => !items.some((item) => item.id === id))) {
      throw new ContractError('prune.acceptances', 'impact must refer only to selected evidence');
    }
    return { approval: parseApprovalReference(item.approval), revision: parseDigest(item.revision), affectedEvidence };
  })].sort((a, b) => a.approval.id < b.approval.id ? -1 : a.approval.id > b.approval.id ? 1 : 0);
  unique(acceptances.map((item) => item.approval.id), 'prune.acceptances');
  if (items.length > 64 || acceptances.length > 512) {
    throw new ContractError('prune.inventory', 'at most 64 files and 512 affected acceptance records may be reviewed together');
  }
  const material = { schemaVersion: 1 as const, workspace: parseWorkspaceBinding(input.workspace), items, acceptances };
  return { ...material, digest: digestContent(JSON.stringify(material)) };
}

export function parsePruneInventory(value: unknown): EvidencePruneInventory {
  const input = record(value, 'prune.inventory', ['schemaVersion', 'workspace', 'items', 'acceptances', 'digest']);
  const parsed = makePruneInventory({
    schemaVersion: oneVersion(input.schemaVersion), workspace: parseWorkspaceBinding(input.workspace),
    items: array(input.items, 'prune.items', parsePruneTarget),
    acceptances: array(input.acceptances, 'prune.acceptances', (value) => {
      const item = record(value, 'prune.acceptance', ['approval', 'revision', 'affectedEvidence']);
      return {
        approval: parseApprovalReference(item.approval), revision: parseDigest(item.revision),
        affectedEvidence: array(item.affectedEvidence, 'prune.affectedEvidence', (id) => parseId('evidence', id)),
      };
    }),
  });
  if (parsed.digest !== parseDigest(input.digest)) throw new ContractError('prune.inventory.digest', 'content does not match');
  return parsed;
}

function oneVersion(value: unknown): 1 {
  if (value !== 1) throw new ContractError('prune.schemaVersion', 'unsupported version');
  return value;
}

export function parsePruneObservation(value: unknown): EvidencePruneObservation {
  const input = record(value, 'prune.observation', ['evidenceId', 'basis', 'result', 'outputDigest']);
  return {
    evidenceId: parseId('evidence', input.evidenceId),
    basis: oneOf(input.basis, ['executed', 'static-inspection', 'agent-review'], 'prune.observation.basis'),
    result: oneOf(input.result, ['passed', 'failed'], 'prune.observation.result'),
    outputDigest: parseDigest(input.outputDigest),
  };
}

export function makePrunePlan(inventory: EvidencePruneInventory, observations: readonly EvidencePruneObservation[]): EvidencePrunePlan {
  const observed = [...array(observations, 'prune.observations', parsePruneObservation)].sort((a, b) =>
    a.evidenceId < b.evidenceId ? -1 : a.evidenceId > b.evidenceId ? 1 : 0);
  const parsed = parsePruneInventory(inventory);
  if (observed.length !== parsed.items.length || observed.some((item, index) => item.evidenceId !== parsed.items[index]?.id)) {
    throw new ContractError('prune.observations', 'every selected raw file requires exactly one actual observation summary');
  }
  const material = { schemaVersion: 1 as const, inventory: parsed, observations: observed };
  return { ...material, digest: digestContent(JSON.stringify(material)) };
}

export function parsePrunePlan(value: unknown): EvidencePrunePlan {
  const input = record(value, 'prune.plan', ['schemaVersion', 'inventory', 'observations', 'digest']);
  oneVersion(input.schemaVersion);
  const parsed = makePrunePlan(parsePruneInventory(input.inventory), array(input.observations, 'prune.observations', parsePruneObservation));
  if (parsed.digest !== parseDigest(input.digest)) throw new ContractError('prune.plan.digest', 'content does not match');
  return parsed;
}

export function evidencePruneRequest(value: EvidencePrunePlan): ApprovalRequest {
  const plan = parsePrunePlan(value);
  const effects = plan.inventory.items.map((item) => ({
    kind: 'file-remove' as const, purpose: 'closure' as const, path: item.path, expected: item.rawDigest,
  }));
  return parseApprovalRequest({
    contractVersion: 1, state: 'untrusted-request', operation: 'verify', purpose: 'verification', effects,
    binding: { kind: 'project', workspace: plan.inventory.workspace, revision: plan.digest, effects: digestEffectScope(effects) },
  });
}

export function parsePrunePrepared(value: unknown): EvidencePrunePrepared {
  const input = record(value, 'prune.prepared', ['schemaVersion', 'id', 'plan', 'request', 'approval', 'preparedAt']);
  const plan = parsePrunePlan(input.plan);
  const request = parseApprovalRequest(input.request);
  if (parseDigest(input.id) !== plan.digest || digestApprovalRequest(request) !== digestApprovalRequest(evidencePruneRequest(plan))) {
    throw new ContractError('prune.prepared', 'identity and exact removal request must bind the reviewed plan');
  }
  return {
    schemaVersion: oneVersion(input.schemaVersion), id: plan.digest, plan, request,
    approval: parseApprovalReference(input.approval), preparedAt: timestamp(input.preparedAt),
  };
}

export function parsePruneCompletion(value: unknown): EvidencePruneCompletion {
  const input = record(value, 'prune.completion', ['schemaVersion', 'id', 'preparedDigest', 'approval', 'completedAt']);
  return {
    schemaVersion: oneVersion(input.schemaVersion), id: parseDigest(input.id), preparedDigest: parseDigest(input.preparedDigest),
    approval: parseApprovalReference(input.approval), completedAt: timestamp(input.completedAt),
  };
}
