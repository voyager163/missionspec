import { parseId, parseProjectPath } from '../../../kernel/identifiers.js';
import { digestContent, parseDigest, type ContentDigest } from '../../../kernel/revisions.js';
import { array, ContractError, record, text, unique } from '../../../kernel/validation.js';
import {
  captureArtifactSnapshot, parseArtifactNodeId, parseMarkdownSet,
  type ArtifactDependency, type ArtifactNodeId, type ArtifactSnapshot,
} from '../../specification/contracts.js';
import type {
  ArtifactApplicability, ArtifactBinding, ArtifactReadinessAssessment, ArtifactReadinessReport, ReadinessDiagnostic,
} from './types.js';
import { dependencyClosure, parseArtifactWorkflow } from './workflow.js';

function parseDependencies(value: unknown): readonly ArtifactDependency[] {
  const dependencies = array(value, 'dependencies', (entry) => {
    const dependency = record(entry, 'dependency', ['artifactId', 'revision']);
    return Object.freeze({
      artifactId: parseId('artifact', dependency.artifactId), revision: parseDigest(dependency.revision),
    });
  });
  unique(dependencies.map((dependency) => dependency.artifactId), 'dependencies');
  return dependencies;
}

function parseApplicability(value: unknown): ArtifactApplicability {
  const input = record(value, 'applicability', ['state', 'reason', 'sourceRevision', 'dependencies']);
  if (input.state === 'required') {
    record(value, 'applicability', ['state']);
    return Object.freeze({ state: 'required' });
  }
  if (input.state === 'not-applicable') {
    return Object.freeze({
      state: 'not-applicable', reason: text(input.reason, 'applicability.reason'),
      sourceRevision: parseDigest(input.sourceRevision),
      dependencies: parseDependencies(input.dependencies),
    });
  }
  throw new ContractError('applicability.state', 'expected required or not-applicable');
}

function parseBinding(value: unknown): ArtifactBinding {
  const input = record(value, 'binding', ['node', 'artifactId', 'declaredOutputs', 'applicability']);
  return Object.freeze({
    node: parseArtifactNodeId(input.node),
    artifactId: parseId('artifact', input.artifactId),
    declaredOutputs: unique(array(input.declaredOutputs, 'binding.declaredOutputs', parseProjectPath, 1), 'binding.declaredOutputs'),
    applicability: parseApplicability(input.applicability),
  });
}

export function notApplicableArtifactRevision(value: unknown): ContentDigest {
  const input = record(value, 'skip', ['node', 'artifactId', 'reason', 'sourceRevision', 'workflowRevision', 'dependencies']);
  return digestContent(JSON.stringify({
    state: 'not-applicable',
    node: parseArtifactNodeId(input.node),
    artifactId: parseId('artifact', input.artifactId),
    reason: text(input.reason, 'skip.reason'),
    sourceRevision: parseDigest(input.sourceRevision),
    workflowRevision: parseDigest(input.workflowRevision),
    dependencies: [...parseDependencies(input.dependencies)].sort((left, right) =>
      left.artifactId < right.artifactId ? -1 : left.artifactId > right.artifactId ? 1 : 0),
  }));
}

function validateSnapshot(value: unknown): ArtifactSnapshot {
  const input = record(value, 'snapshot', ['contractVersion', 'id', 'node', 'files', 'dependencies', 'revision']);
  const files = array(input.files, 'snapshot.files', (entry) => {
    const file = record(entry, 'snapshot.file', ['path', 'content', 'digest']);
    const content = text(file.content, 'snapshot.file.content', 1_000_000);
    if (parseDigest(file.digest) !== digestContent(content)) {
      throw new ContractError('snapshot.file.digest', 'content does not match its supplied digest');
    }
    return Object.freeze({ path: parseProjectPath(file.path), content });
  }, 1);
  const snapshot = captureArtifactSnapshot({
    contractVersion: input.contractVersion, id: input.id, node: input.node,
    files, dependencies: input.dependencies,
  });
  if (snapshot.revision !== parseDigest(input.revision)) {
    throw new ContractError('snapshot.revision', 'snapshot does not match its supplied revision');
  }
  return snapshot;
}

export function assessArtifactReadiness(value: unknown): ArtifactReadinessReport {
  const input = record(value, 'readiness', [
    'changeId', 'workflowSource', 'expectedWorkflow', 'sourceRevision', 'bindings', 'snapshots', 'selected', 'targets',
  ]);
  const changeId = parseId('change', input.changeId);
  const workflow = parseArtifactWorkflow(input.workflowSource);
  if (parseDigest(input.expectedWorkflow) !== workflow.revision) {
    throw new ContractError('readiness.expectedWorkflow', 'the supplied workflow differs from the pinned revision');
  }
  const sourceRevision = parseDigest(input.sourceRevision);
  const bindings = array(input.bindings, 'readiness.bindings', parseBinding);
  unique(bindings.map((binding) => binding.node), 'readiness.bindings');
  unique(bindings.map((binding) => binding.artifactId), 'readiness.bindings');
  unique(bindings.flatMap((binding) => binding.declaredOutputs), 'readiness.declaredOutputs');
  if (bindings.length !== workflow.nodes.length) {
    throw new ContractError('readiness.bindings', 'bind every workflow node exactly once');
  }
  const byNode = new Map(bindings.map((binding) => [binding.node, binding]));
  for (const node of workflow.nodes) {
    const binding = byNode.get(node.id);
    if (binding === undefined) throw new ContractError('readiness.bindings', 'missing workflow node binding');
    if (node.outputMode === 'single' && binding.declaredOutputs.length !== 1) {
      throw new ContractError('readiness.declaredOutputs', 'this artifact declares exactly one output');
    }
    if (node.outputMode === 'task-set' && (binding.declaredOutputs.length > 2 ||
        !binding.declaredOutputs[0]?.endsWith('/tasks.md') ||
        binding.declaredOutputs.length === 2 && binding.declaredOutputs[1] !== binding.declaredOutputs[0].replace(/tasks\.md$/u, 'verification.md'))) {
      throw new ContractError('readiness.declaredOutputs', 'tasks declares tasks.md and optionally its sibling verification.md');
    }
    if (node.skip === 'never' && binding.applicability.state !== 'required') {
      throw new ContractError('readiness.applicability', 'this artifact cannot be skipped by the built-in workflow');
    }
  }
  const snapshots = new Map<ArtifactNodeId, ArtifactSnapshot>();
  const invalidSnapshots = new Set<ArtifactNodeId>();
  const suppliedNodes = new Set<ArtifactNodeId>();
  for (const entry of array(input.snapshots, 'readiness.snapshots', (item) => item)) {
    const row = record(entry, 'snapshot', ['contractVersion', 'id', 'node', 'files', 'dependencies', 'revision']);
    const node = parseArtifactNodeId(row.node);
    if (!byNode.has(node)) throw new ContractError('readiness.snapshots', 'snapshot belongs to an undeclared node');
    if (suppliedNodes.has(node)) throw new ContractError('readiness.snapshots', 'duplicate snapshot for one artifact');
    suppliedNodes.add(node);
    try {
      snapshots.set(node, validateSnapshot(entry));
    } catch {
      invalidSnapshots.add(node);
    }
  }
  const documents = parseMarkdownSet([...snapshots.values()].flatMap((snapshot) =>
    snapshot.files.map((file) => ({ path: file.path, content: file.content })),
  ));
  const parsedDocuments = documents.state === 'valid' ? documents.documents : documents.parsedDocuments;
  const parsedByPath = new Map(parsedDocuments.map((document) => [document.path, document]));
  const documentDiagnostics = documents.state === 'invalid' ? documents.diagnostics : [];
  const assessments = new Map<ArtifactNodeId, ArtifactReadinessAssessment>();
  const definitions = new Map(workflow.nodes.map((node) => [node.id, node]));
  for (const id of workflow.order) {
    const node = definitions.get(id);
    const binding = byNode.get(id);
    if (node === undefined || binding === undefined) throw new ContractError('readiness', 'invalid workflow binding');
    const diagnostics: ReadinessDiagnostic[] = [];
    const add = (
      code: ReadinessDiagnostic['code'], message: string, document: ReadinessDiagnostic['document'] = null,
    ): void => { diagnostics.push(Object.freeze({ node: id, code, message, document })); };
    const snapshot = snapshots.get(id);
    let readiness: ArtifactReadinessAssessment['readiness'] = 'valid';
    let revision: ContentDigest | null = snapshot?.revision ?? null;
    if (binding.applicability.state === 'not-applicable') {
      revision = notApplicableArtifactRevision({
        node: id, artifactId: binding.artifactId, reason: binding.applicability.reason,
        sourceRevision: binding.applicability.sourceRevision, workflowRevision: workflow.revision,
        dependencies: binding.applicability.dependencies,
      });
      readiness = 'not-applicable';
      if (suppliedNodes.has(id)) {
        readiness = 'blocked';
        add('skip-has-content', 'A skipped artifact cannot also have supplied content.');
      } else if (binding.applicability.sourceRevision !== sourceRevision) {
        readiness = 'stale';
        add('skip-stale', 'Review the applicability decision against the current supplied source revision.');
      }
    } else if (invalidSnapshots.has(id)) {
      readiness = 'blocked';
      add('invalid-snapshot', 'Snapshot structure, content digests or revision identity is invalid.');
    } else if (snapshot === undefined) {
      readiness = 'missing';
      add('missing-snapshot', 'No snapshot was supplied for this required artifact.');
    } else {
      if (snapshot.id !== binding.artifactId ||
        snapshot.files.length !== binding.declaredOutputs.length ||
        binding.declaredOutputs.some((path) => !snapshot.files.some((file) => file.path === path))) {
        readiness = 'blocked';
        add('output-set-mismatch', 'Snapshot identity and exact output set must match the declaration.');
      }
      for (const file of snapshot.files) {
        const document = parsedByPath.get(file.path);
        for (const problem of documentDiagnostics.filter((entry) => entry.location.path === file.path)) {
          readiness = 'blocked';
          add('invalid-document', 'The supplied Markdown set has structural or reference diagnostics.', problem);
        }
        if (document === undefined) {
          readiness = 'blocked';
        } else if (document.kind !== (node.kind === 'tasks' && file.path.endsWith('/verification.md') ? 'verification' : node.kind)) {
          readiness = 'blocked';
          add('document-kind-mismatch', 'Document kind does not match its workflow artifact node.');
        } else if (document.changeId !== changeId) {
          readiness = 'blocked';
          add('document-change-mismatch', 'Document identity belongs to a different change than the requested scope.');
        } else if (document.kind === 'tasks' && node.additionalSections.some((section) => !document.sections.some((entry) => entry.name === section))) {
          readiness = 'blocked';
          add('additional-section-missing', 'This workflow requires a combined Design section in tasks.');
        }
      }
    }
    const recordedDependencies = binding.applicability.state === 'not-applicable' ?
      binding.applicability.dependencies : snapshot?.dependencies;
    if (recordedDependencies !== undefined) {
      const expectedIds = node.dependsOn.map((dependency) => byNode.get(dependency)?.artifactId);
      if (recordedDependencies.length !== expectedIds.length ||
        expectedIds.some((artifactId) => !recordedDependencies.some((entry) => entry.artifactId === artifactId))) {
        readiness = 'blocked';
        add('dependency-set-mismatch', 'Prepared content or skip decisions must name the exact declared predecessor set.');
      }
    }
    for (const dependencyId of node.dependsOn) {
      const dependency = assessments.get(dependencyId);
      if (dependency === undefined) throw new ContractError('readiness', 'dependency was not assessed');
      if (dependency.readiness !== 'valid' && dependency.readiness !== 'not-applicable') {
        if (readiness !== 'blocked') {
          readiness = recordedDependencies !== undefined && dependency.readiness === 'stale' ? 'stale' : 'blocked';
        }
        add('dependency-not-current', 'A required predecessor is not current and structurally valid.');
      } else if (recordedDependencies !== undefined) {
        const recorded = recordedDependencies.find((entry) => entry.artifactId === dependency.artifactId);
        if (recorded !== undefined && recorded.revision !== dependency.revision) {
          if (readiness !== 'blocked') readiness = 'stale';
          add('dependency-revision-mismatch', 'A predecessor differs from the frozen dependency revision.');
        }
      }
    }
    assessments.set(id, Object.freeze({
      node: id, artifactId: binding.artifactId, readiness, revision, diagnostics: Object.freeze(diagnostics),
    }));
  }
  const targets = input.targets === undefined ? workflow.targets :
    unique(array(input.targets, 'readiness.targets', parseArtifactNodeId, 1), 'readiness.targets');
  const closure = dependencyClosure(workflow, targets);
  const requiredClosure = Object.freeze(closure.filter((id) => byNode.get(id)?.applicability.state === 'required'));
  const remainingClosure = Object.freeze(requiredClosure.filter((id) => assessments.get(id)?.readiness !== 'valid'));
  const candidates = Object.freeze(remainingClosure.filter((id) => {
    const assessment = assessments.get(id);
    const node = definitions.get(id);
    return (assessment?.readiness === 'missing' || assessment?.readiness === 'stale') &&
      node?.dependsOn.every((dependency) => {
        const state = assessments.get(dependency)?.readiness;
        return state === 'valid' || state === 'not-applicable';
      });
  }));
  const selected = input.selected === undefined || input.selected === null ? null : parseArtifactNodeId(input.selected);
  if (selected !== null && !definitions.has(selected)) throw new ContractError('readiness.selected', 'unknown artifact selector');
  const ordered = Object.freeze(workflow.order.map((id) => {
    const assessment = assessments.get(id);
    if (assessment === undefined) throw new ContractError('readiness', 'missing assessment');
    return assessment;
  }));
  const diagnostics = ordered.flatMap((assessment) => assessment.diagnostics);
  let next: ArtifactReadinessReport['next'];
  if (selected !== null) {
    if (candidates.includes(selected)) next = Object.freeze({ state: 'ready', node: selected });
    else {
      next = Object.freeze({ state: 'blocked' });
      diagnostics.push(Object.freeze({
        node: selected, code: 'selection-not-actionable',
        message: 'The selected artifact is not an eligible next draft in the requested closure.', document: null,
      }));
    }
  } else if (closure.every((id) => ['valid', 'not-applicable'].includes(assessments.get(id)?.readiness ?? 'blocked'))) {
    next = Object.freeze({ state: 'all-current' });
  } else if (candidates.length === 1) {
    const node = candidates[0];
    if (node === undefined) throw new ContractError('readiness', 'invalid selection');
    next = Object.freeze({ state: 'ready', node });
  } else if (candidates.length > 1) next = Object.freeze({ state: 'selection-required', candidates });
  else next = Object.freeze({ state: 'blocked' });
  return Object.freeze({
    profile: workflow.profile, workflowRevision: workflow.revision, assessments: ordered,
    requiredClosure, remainingClosure, next, diagnostics: Object.freeze(diagnostics),
  });
}
