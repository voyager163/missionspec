import { isDeepStrictEqual } from 'node:util';
import { closed, digest, digestJson, fail } from './definition.mjs';
import { PRIVATE_LINK_CONTROL_STAGES } from './private-link.mjs';
import { load, save, saveImmutable, privateDirectory, MAX_PRIVATE_ARTIFACT_BYTES } from './controller.mjs';

const envelopeKind = 'private-link-artifact-envelope';
const referenceKind = 'private-link-control-evidence-reference';
const candidateReferenceKind = 'private-link-receiver-candidate-reference';
const recoveryReferenceKind = 'private-link-continued-recovery-reference';
const recoveryContentKind = 'private-link-continued-recovery-content';
const completionReferenceKind = 'private-link-runtime-completion-reference';
const completionTemplateKind = 'private-link-runtime-completion-template';
const localPrefixKind = 'private-link-local-control-prefix-reference';
const controlKind = 'reviewed-private-link-control-chain';
const owners = new Set(['private-link-runtime-completion', 'private-link-disabled-receiver',
  'private-link-reconciled-disabled-receiver', 'private-link-receiver-create-intent', 'private-link-window-intent']);
const maximumReferences = 64, maximumDistinctReferences = 8, maximumDepth = 128, maximumNodes = 4 * 1024 * 1024;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const evidenceName = (sha, version = 1) => `private-link-evidence-${version === 2 ? 'v2-' : ''}${sha}.json`;
const candidateName = sha => `private-link-candidate-${sha}.json`;
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
const prefixStages = PRIVATE_LINK_CONTROL_STAGES.slice(0, PRIVATE_LINK_CONTROL_STAGES.indexOf('assign-queue-role') + 1);
const recoveryKeys = ['version', 'kind', 'stage', 'phase', 'publication', 'approval', 'preflight', 'intent',
  'intentSha256', 'journal', 'after', 'deployment', 'operations', 'completedAt', 'authority', 'recovery'];
const reservedKinds = new Set([envelopeKind, referenceKind, candidateReferenceKind, recoveryReferenceKind, recoveryContentKind,
  completionReferenceKind, completionTemplateKind, localPrefixKind]);
const completionName = hash => `private-link-completion-template-${hash}.json`;

function compact(value) {
  const bytes = JSON.stringify(value) + '\n';
  if (Buffer.byteLength(bytes) > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_LINK_ARTIFACT_TOO_LARGE');
  return bytes;
}
function evidenceShape(value) {
  closed(value, ['version', 'kind', 'planSha256', 'originSha256', 'records',
    ...(value?.version === 2 ? ['externalAdoption'] : [])]);
  if (![1, 2].includes(value.version) || value.kind !== controlKind ||
      !sha(value.planSha256) || !sha(value.originSha256) || !Array.isArray(value.records) ||
      value.records.length !== prefixStages.length || value.records.some((record, index) => record?.stage !== prefixStages[index])) {
    fail('PRIVATE_LINK_ARTIFACT_EVIDENCE_SCOPE');
  }
}
function candidateShape(value) {
  closed(value, ['version', 'profile', 'review', 'legacyPublication', 'publication', 'priorCandidate', 'topology']);
  if (value.version !== 2 || value.profile?.version !== 2 ||
      value.profile.kind !== 'reviewed-durable-queue-receiver' ||
      !/^sha256:[a-f0-9]{64}$/u.test(value.profile.manifestDigest ?? '') ||
      !/^sha256:[a-f0-9]{64}$/u.test(value.profile.configDigest ?? '') ||
      !isObject(value.review) || !isObject(value.legacyPublication) ||
      value.publication !== null && !isObject(value.publication) ||
      value.priorCandidate?.version !== 1 || !isObject(value.topology)) fail('PRIVATE_LINK_ARTIFACT_CANDIDATE_SCOPE');
}
function continuedRecovery(value) {
  return value?.version === 3 && value.kind === 'reviewed-private-link-recovery' &&
    prefixStages.includes(value.stage) && value.phase?.continuation !== undefined;
}
function recoveryShape(value) {
  closed(value, recoveryKeys);
  const original = value.recovery?.original;
  if (!continuedRecovery(value) || value.phase?.kind !== 'fixed-private-link-control-phase' ||
      value.phase.stage !== value.stage || value.phase.continuation?.version !== 1 ||
      value.phase.continuation.kind !== 'reviewed-private-link-no-submission-continuation' ||
      value.preflight?.kind !== 'checked-private-link-phase' || value.preflight.runtimeCompletion !== null ||
      !isObject(original)) fail('PRIVATE_LINK_ARTIFACT_RECOVERY_SCOPE');
  closed(original, ['phase', 'publication', 'approval', 'preflight', 'journal', 'intent']);
  for (const key of ['phase', 'preflight']) {
    if (!isDeepStrictEqual(value[key], original[key]) || digestJson(value[key]) !== digestJson(original[key])) {
      fail('PRIVATE_LINK_ARTIFACT_RECOVERY_MEMBER_CHANGED');
    }
  }
}
function projectRecovery(value, recordSha256) {
  const payload = Object.fromEntries(Object.entries(value).map(([key, entry]) =>
    [key, key === 'phase' || key === 'preflight' ? null : entry]));
  return { version: 1, kind: recoveryContentKind, recordSha256, payloadSha256: digest(compact(payload)), payload };
}
function restoreRecovery(value, expectedSha256, budget = null) {
  closed(value, ['version', 'kind', 'recordSha256', 'payloadSha256', 'payload']);
  if (value.version !== 1 || value.kind !== recoveryContentKind || value.recordSha256 !== expectedSha256 ||
      !sha(value.payloadSha256) || digest(compact(value.payload)) !== value.payloadSha256) {
    fail('PRIVATE_LINK_ARTIFACT_RECOVERY_CONTENT_CHANGED');
  }
  closed(value.payload, recoveryKeys);
  if (value.payload.phase !== null || value.payload.preflight !== null ||
      !isObject(value.payload.recovery?.original)) fail('PRIVATE_LINK_ARTIFACT_RECOVERY_PROJECTION_INVALID');
  noReferences(value.payload, budget);
  // Keep the original key positions as well as the exact original member bytes.
  return Object.fromEntries(Object.entries(value.payload).map(([key, entry]) =>
    [key, key === 'phase' || key === 'preflight' ? value.payload.recovery.original[key] : entry]));
}
const referenceTypes = {
  controlEvidence: { kind: referenceKind, hashField: 'evidenceSha256', name: evidenceName, verify: evidenceShape, versions: [1, 2] },
  candidate: { kind: candidateReferenceKind, hashField: 'candidateSha256', name: candidateName, verify: candidateShape, versions: [1] },
};
const recoveryType = { kind: recoveryReferenceKind, hashField: 'recordSha256',
  name: hash => `private-link-continued-recovery-${hash}.json`, verify: recoveryShape, versions: [1] };
const referenceKinds = new Set([referenceKind, candidateReferenceKind, recoveryReferenceKind]);
function referenceShape(value, type) {
  closed(value, ['version', 'kind', type.hashField, 'bytes']);
  if (!type.versions.includes(value.version) || value.kind !== type.kind || !sha(value[type.hashField]) ||
      !Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > MAX_PRIVATE_ARTIFACT_BYTES) {
    fail('PRIVATE_LINK_ARTIFACT_REFERENCE_INVALID');
  }
}
function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}
function walker(budget = null) {
  let nodes = 0;
  const ancestors = new Set();
  return async function walk(value, visit, parent = null, key = null, depth = 0, owner = null) {
    if (++nodes > maximumNodes || depth > maximumDepth ||
        budget && ++budget.nodes > maximumNodes) fail('PRIVATE_LINK_ARTIFACT_STRUCTURE_LIMIT');
    if (value === null || ['string', 'boolean'].includes(typeof value) ||
        typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value !== 'object' || ancestors.has(value)) fail('PRIVATE_LINK_ARTIFACT_JSON_REQUIRED');
    const replacement = await visit(value, parent, key, owner);
    if (replacement !== undefined) return replacement;
    ancestors.add(value);
    try {
      if (Array.isArray(value)) {
        const result = [];
        for (const [index, entry] of value.entries()) result.push(await walk(entry, visit, value, index, depth + 1, { parent, key, owner }));
        return result;
      }
      if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('PRIVATE_LINK_ARTIFACT_JSON_REQUIRED');
      const entries = [];
      for (const [name, entry] of Object.entries(value)) entries.push([name, await walk(entry, visit, value, name, depth + 1, { parent, key, owner })]);
      return Object.fromEntries(entries);
    } finally { ancestors.delete(value); }
  };
}
function noReferences(value, budget = null) {
  let nodes = 0;
  const ancestors = new Set();
  function visit(entry, depth) {
    if (++nodes > maximumNodes || depth > maximumDepth ||
        budget && ++budget.nodes > maximumNodes) fail('PRIVATE_LINK_ARTIFACT_STRUCTURE_LIMIT');
    if (entry === null || ['string', 'boolean'].includes(typeof entry) ||
        typeof entry === 'number' && Number.isFinite(entry)) return;
    if (typeof entry !== 'object' || ancestors.has(entry)) fail('PRIVATE_LINK_ARTIFACT_JSON_REQUIRED');
    if (reservedKinds.has(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
    ancestors.add(entry);
    try { for (const child of Object.values(entry)) visit(child, depth + 1); }
    finally { ancestors.delete(entry); }
  }
  visit(value, 0);
}
function eligible(parent, key, owner) {
  if (Array.isArray(parent) && owner?.key === 'records' && owner.parent?.kind === controlKind) return recoveryType;
  return owners.has(parent?.kind) && Object.hasOwn(referenceTypes, key) ? referenceTypes[key] : null;
}
function memberPath(key, owner) {
  const path = [key];
  for (let current = owner; current && current.key !== null; current = current.owner) path.push(current.key);
  return JSON.stringify(path.reverse());
}
function aggregateCandidate(value) {
  return value?.kind === controlKind && Array.isArray(value.records) && value.records.length > prefixStages.length &&
    value.records.slice(prefixStages.length).some(record => isObject(record?.preflight) && Object.hasOwn(record.preflight, 'kind'));
}
function aggregateSlots(value) {
  closed(value, ['version', 'kind', 'planSha256', 'originSha256', 'records', ...(value?.version === 2 ? ['externalAdoption'] : [])]);
  if (![1, 2].includes(value.version) || value.kind !== controlKind || !sha(value.planSha256) || !sha(value.originSha256) ||
      !Array.isArray(value.records) || value.records.length <= prefixStages.length ||
      value.records.length > PRIVATE_LINK_CONTROL_STAGES.length ||
      value.records.some((record, index) => record?.stage !== PRIVATE_LINK_CONTROL_STAGES[index] &&
        !(index < prefixStages.length && record?.kind === recoveryReferenceKind))) fail('PRIVATE_LINK_ARTIFACT_AGGREGATE_SCOPE');
  const slots = new Set(), active = new Set();
  const original = (value, stage, path, depth) => {
    if (depth > 8 || active.has(value)) fail('PRIVATE_LINK_ARTIFACT_AGGREGATE_HISTORY_LIMIT');
    closed(value, ['phase', 'publication', 'approval', 'preflight', 'journal', 'intent']);
    active.add(value);
    try {
      preflight(value.preflight, [...path, 'preflight']);
      phase(value.phase, stage, [...path, 'phase'], depth);
    } finally { active.delete(value); }
  };
  const preflight = (value, path) => {
    if (value?.kind !== 'checked-private-link-phase' || !isObject(value.runtimeCompletion)) fail('PRIVATE_LINK_ARTIFACT_COMPLETION_POSITION');
    slots.add(JSON.stringify([...path, 'runtimeCompletion']));
  };
  const phase = (value, stage, path, depth) => {
    if (value?.kind !== 'fixed-private-link-control-phase' || value.stage !== stage) fail('PRIVATE_LINK_ARTIFACT_AGGREGATE_STAGE');
    if (value.continuation === undefined) return;
    closed(value.continuation, ['version', 'kind', 'attemptId', 'resolution', 'review']);
    if (value.continuation.version !== 1 || value.continuation.kind !== 'reviewed-private-link-no-submission-continuation' ||
        ![1, 2].includes(value.continuation.resolution?.version) ||
        value.continuation.resolution.kind !== 'reviewed-private-link-no-submission') fail('PRIVATE_LINK_ARTIFACT_AGGREGATE_CONTINUATION');
    closed(value.continuation.resolution, ['version', 'kind', 'original', 'proposal', 'review', 'observed', 'publication',
      'costReview', 'costEvidence', 'migrationReview', 'policyRevision', 'completedAt', 'qualified', 'successfulChainUnchanged',
      'replayAuthorized', 'physicalFenceRetained', 'originalHistoryModified', 'resolution', 'resumable',
      ...(value.continuation.resolution.version === 2 ? ['externalAdoptionSha256'] : [])]);
    original(value.continuation.resolution.original, stage, [...path, 'continuation', 'resolution', 'original'], depth + 1);
  };
  for (let index = prefixStages.length; index < value.records.length; index++) {
    const record = value.records[index], path = ['records', index];
    closed(record, recoveryKeys);
    if (![1, 2, 3].includes(record.version) || !['reviewed-private-link-phase', 'reviewed-private-link-recovery'].includes(record.kind)) {
      fail('PRIVATE_LINK_ARTIFACT_AGGREGATE_RECORD');
    }
    preflight(record.preflight, [...path, 'preflight']);
    phase(record.phase, record.stage, [...path, 'phase'], 0);
    if (record.kind === 'reviewed-private-link-recovery') {
      closed(record.recovery, ['original', 'proposal', 'review', 'costReview', 'costEvidence', 'migrationReview', 'currentPublication', 'policyRevision']);
      original(record.recovery.original, record.stage, [...path, 'recovery', 'original'], 0);
    } else if (record.recovery !== null) fail('PRIVATE_LINK_ARTIFACT_AGGREGATE_RECORD');
  }
  return slots;
}
function aggregatePrefix(value) {
  const prefix = Object.fromEntries(Object.entries(value).map(([key, entry]) =>
    [key, key === 'records' ? entry.slice(0, prefixStages.length) : entry]));
  evidenceShape(prefix);
  return prefix;
}
function completionShape(value) {
  if (value?.version !== 1 || value.kind !== 'private-link-runtime-completion' || !isObject(value.controlEvidence)) {
    fail('PRIVATE_LINK_ARTIFACT_COMPLETION_SCOPE');
  }
}
function completionReference(value) {
  closed(value, ['version', 'kind', 'completionSha256', 'prefixSha256', 'bytes']);
  if (value.version !== 1 || value.kind !== completionReferenceKind || !sha(value.completionSha256) ||
      !sha(value.prefixSha256) || !Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > MAX_PRIVATE_ARTIFACT_BYTES) {
    fail('PRIVATE_LINK_ARTIFACT_COMPLETION_REFERENCE_INVALID');
  }
}

// Ports are trusted internal test dependencies, never artifact-supplied options.
export function createPrivateLinkArtifactStore({ root, read = load, immutable = saveImmutable, update = save }) {
  if (typeof root !== 'string') fail('PRIVATE_LINK_ARTIFACT_STORE_REQUIRED');
  const countReference = state => {
    if (++state.references > maximumReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
  };
  const writeBlob = async (name, build, state) => {
    if (!state.written.has(name)) {
      if (state.written.size >= maximumDistinctReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
      state.written.set(name, null);
      const bytes = await build(), length = Buffer.byteLength(bytes);
      state.bytes += length;
      if (state.bytes > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_BYTES_LIMIT');
      try { await immutable(root, name, bytes); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        if (compact(await read(root, name)) !== bytes) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
      }
      state.written.set(name, length);
    }
    const bytes = state.written.get(name);
    if (bytes === null) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
    return bytes;
  };
  const writeCandidate = async (value, state) => {
    countReference(state);
    if (state.candidates.has(value)) return state.candidates.get(value);
    candidateShape(value); noReferences(value);
    const hash = digestJson(value);
    const bytes = await writeBlob(candidateName(hash), async () => { noReferences(value, state); return compact(value); }, state);
    const reference = { version: 1, kind: candidateReferenceKind, candidateSha256: hash, bytes };
    state.candidates.set(value, reference); return reference;
  };
  const writeCompletion = async (value, aggregate, state) => {
    completionShape(value); countReference(state);
    if (state.completions.has(value)) return state.completions.get(value);
    const hash = digestJson(value), name = completionName(hash);
    const bytes = await writeBlob(name, async () => {
      let referenceCount = 0;
      const payload = await walker(state)(value, async (entry, parent, key) => {
        if (reservedKinds.has(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_ALREADY_ENCODED');
        if (!owners.has(parent?.kind)) return undefined;
        if (key === 'controlEvidence') {
          evidenceShape(entry);
          if (!isDeepStrictEqual(entry, aggregate.prefix) || digestJson(entry) !== aggregate.prefixSha256) {
            fail('PRIVATE_LINK_ARTIFACT_LOCAL_PREFIX_CHANGED');
          }
          referenceCount++; countReference(state);
          return { version: 1, kind: localPrefixKind, evidenceSha256: aggregate.prefixSha256 };
        }
        if (key === 'candidate') { referenceCount++; return writeCandidate(entry, state); }
        return undefined;
      });
      return compact({ version: 1, kind: completionTemplateKind, completionSha256: hash,
        prefixSha256: aggregate.prefixSha256, referenceCount, payloadSha256: digest(compact(payload)), payload });
    }, state);
    const reference = { version: 1, kind: completionReferenceKind, completionSha256: hash, prefixSha256: aggregate.prefixSha256, bytes };
    state.completions.set(value, reference); return reference;
  };
  const readCompletion = async (reference, aggregate, state) => {
    completionReference(reference);
    if (reference.prefixSha256 !== aggregate.prefixSha256) fail('PRIVATE_LINK_ARTIFACT_LOCAL_PREFIX_CHANGED');
    const name = completionName(reference.completionSha256);
    if (state.loaded.has(name)) {
      const prior = state.loaded.get(name);
      if (prior.bytes !== reference.bytes) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
      return prior.value;
    }
    if (state.active.has(name)) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
    if (state.loaded.size + state.active.size >= maximumDistinctReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
    state.bytes += reference.bytes;
    if (state.bytes > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_BYTES_LIMIT');
    state.active.add(name);
    try {
      const template = await read(root, name);
      if (Buffer.byteLength(compact(template)) !== reference.bytes) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
      closed(template, ['version', 'kind', 'completionSha256', 'prefixSha256', 'referenceCount', 'payloadSha256', 'payload']);
      if (template.version !== 1 || template.kind !== completionTemplateKind || template.completionSha256 !== reference.completionSha256 ||
          template.prefixSha256 !== aggregate.prefixSha256 || !Number.isSafeInteger(template.referenceCount) ||
          template.referenceCount < 1 || template.referenceCount > maximumReferences ||
          template.payloadSha256 !== digest(compact(template.payload))) fail('PRIVATE_LINK_ARTIFACT_COMPLETION_CONTENT_CHANGED');
      let references = 0;
      const value = await walker(state)(template.payload, async (entry, parent, key) => {
        if (owners.has(parent?.kind) && key === 'controlEvidence' && entry.kind !== localPrefixKind ||
            owners.has(parent?.kind) && key === 'candidate' && entry.kind !== candidateReferenceKind) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_SCOPE');
        if (entry.kind === localPrefixKind) {
          if (!owners.has(parent?.kind) || key !== 'controlEvidence') fail('PRIVATE_LINK_ARTIFACT_LOCAL_PREFIX_SCOPE');
          closed(entry, ['version', 'kind', 'evidenceSha256']);
          if (entry.version !== 1 || entry.evidenceSha256 !== aggregate.prefixSha256) fail('PRIVATE_LINK_ARTIFACT_LOCAL_PREFIX_CHANGED');
          countReference(state); references++; return aggregate.prefix;
        }
        if (entry.kind === candidateReferenceKind) {
          if (!owners.has(parent?.kind) || key !== 'candidate') fail('PRIVATE_LINK_ARTIFACT_REFERENCE_SCOPE');
          countReference(state); references++;
          return readContent(entry, referenceTypes.candidate, state);
        }
        if (reservedKinds.has(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
        return undefined;
      });
      if (references !== template.referenceCount) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_COUNT_CHANGED');
      completionShape(value);
      if (!isDeepStrictEqual(value.controlEvidence, aggregate.prefix) || digestJson(value) !== reference.completionSha256) {
        fail('PRIVATE_LINK_ARTIFACT_COMPLETION_CONTENT_CHANGED');
      }
      const frozen = freeze(value);
      state.loaded.set(name, { bytes: reference.bytes, value: frozen });
      return frozen;
    } finally { state.active.delete(name); }
  };
  const readContent = async (reference, type, state) => {
    referenceShape(reference, type);
    const name = type.name(reference[type.hashField], reference.version);
    if (state.loaded.has(name)) {
      const prior = state.loaded.get(name);
      if (prior.bytes !== reference.bytes) fail('PRIVATE_LINK_ARTIFACT_EVIDENCE_CHANGED');
      return prior.value;
    }
    if (state.active.has(name)) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
    if (state.loaded.size + state.active.size >= maximumDistinctReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
    state.bytes += reference.bytes;
    if (state.bytes > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_BYTES_LIMIT');
    state.active.add(name);
    try {
      const stored = await read(root, name);
      if (Buffer.byteLength(compact(stored)) !== reference.bytes) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
      let value;
      if (type === recoveryType) value = restoreRecovery(stored, reference.recordSha256, state.aggregate ? state : null);
      else if (type === referenceTypes.controlEvidence && reference.version === 2) {
        if (stored?.kind !== envelopeKind || stored.version !== 2) fail('PRIVATE_LINK_ARTIFACT_ENVELOPE_INVALID');
        value = await decodeEnvelope(stored, state, true);
      } else { noReferences(stored, state.aggregate ? state : null); value = stored; }
      type.verify(value);
      if (digestJson(value) !== reference[type.hashField]) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
      value = freeze(value);
      state.loaded.set(name, { bytes: reference.bytes, value });
      return value;
    } finally { state.active.delete(name); }
  };
  const encodePayload = async (value, state, recoveryOnly = false, aggregate = null) => {
    let references = 0, modern = false;
    const payload = await walker(state.aggregate ? state : null)(value, async (entry, parent, key, owner) => {
      if (reservedKinds.has(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_ALREADY_ENCODED');
      if (aggregate?.slots.has(memberPath(key, owner))) {
        references++;
        return writeCompletion(entry, aggregate, state);
      }
      const type = eligible(parent, key, owner);
      if (!type || type === recoveryType && !continuedRecovery(entry)) return undefined;
      if (recoveryOnly && type !== recoveryType) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_SCOPE');
      const snapshot = structuredClone(entry);
      type.verify(snapshot); noReferences(snapshot);
      if (++state.references > maximumReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
      references++;
      const hash = digestJson(snapshot);
      const version = type === referenceTypes.controlEvidence && snapshot.records.some(continuedRecovery) ? 2 : 1;
      modern ||= type === recoveryType || version === 2;
      const name = type.name(hash, version);
      if (!state.written.has(name)) {
        if (state.written.size >= maximumDistinctReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
        state.written.set(name, null);
        const projected = type === recoveryType ? projectRecovery(snapshot, hash) : null;
        if (projected && state.aggregate) noReferences(projected.payload, state);
        if (!projected && version !== 2 && state.aggregate) noReferences(snapshot, state);
        const bytes = projected ? compact(projected) :
          version === 2 ? await encodePayload(snapshot, state, true) : compact(snapshot);
        const length = Buffer.byteLength(bytes);
        state.bytes += length;
        if (state.bytes > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_BYTES_LIMIT');
        try { await immutable(root, name, bytes); }
        catch (error) {
          if (error.code !== 'EEXIST') throw error;
          if (compact(await read(root, name)) !== bytes) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
        }
        state.written.set(name, length);
      }
      const bytes = state.written.get(name);
      if (bytes === null) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
      return { version, kind: type.kind, [type.hashField]: hash, bytes };
    });
    if (aggregate) return compact({ version: 3, kind: envelopeKind, referenceCount: references,
      rootSha256: aggregate.rootSha256, prefixSha256: aggregate.prefixSha256, payloadSha256: digest(compact(payload)), payload });
    if (!references) return compact(payload);
    const bytes = compact(payload);
    return compact({ version: modern ? 2 : 1, kind: envelopeKind, referenceCount: references, payloadSha256: digest(bytes), payload });
  };
  const encode = value => {
    const state = { references: 0, bytes: 0, written: new Map() };
    if (!aggregateCandidate(value)) return encodePayload(value, state);
    // Private copies let repeated object identities share hashing only inside
    // this write, without freezing caller data or trusting a prior operation.
    const snapshot = structuredClone(value), slots = aggregateSlots(snapshot), prefix = aggregatePrefix(snapshot);
    Object.assign(state, { aggregate: true, nodes: 0, candidates: new WeakMap(), completions: new WeakMap() });
    return encodePayload(snapshot, state, false, { slots, prefix, prefixSha256: digestJson(prefix), rootSha256: digestJson(snapshot) });
  };
  const decodeEnvelope = async (value, state, recoveryOnly = false) => {
    closed(value, ['version', 'kind', 'referenceCount', 'payloadSha256', 'payload']);
    if (![1, 2].includes(value.version) || !Number.isSafeInteger(value.referenceCount) || value.referenceCount < 1 ||
        value.referenceCount > maximumReferences || !sha(value.payloadSha256) ||
        digest(compact(value.payload)) !== value.payloadSha256) fail('PRIVATE_LINK_ARTIFACT_ENVELOPE_INVALID');
    let references = 0;
    const result = await walker(state.aggregate ? state : null)(value.payload, async (entry, parent, key, owner) => {
      if (reservedKinds.has(entry.kind) && !referenceKinds.has(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
      if (!referenceKinds.has(entry.kind)) return undefined;
      const type = eligible(parent, key, owner);
      if (!type || type.kind !== entry.kind || recoveryOnly && type !== recoveryType) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_SCOPE');
      referenceShape(entry, type);
      if (value.version === 1 && (type === recoveryType || entry.version !== 1)) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_INVALID');
      if (++state.references > maximumReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
      references++;
      return readContent(entry, type, state);
    });
    if (references !== value.referenceCount) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_COUNT_CHANGED');
    return result;
  };
  const decode = async value => {
    if (!isObject(value) || value.kind !== envelopeKind) { noReferences(value); return value; }
    const state = { references: 0, bytes: 0, loaded: new Map(), active: new Set() };
    if (value.version !== 3) return decodeEnvelope(value, state);
    closed(value, ['version', 'kind', 'referenceCount', 'rootSha256', 'prefixSha256', 'payloadSha256', 'payload']);
    if (!Number.isSafeInteger(value.referenceCount) || value.referenceCount < 1 || value.referenceCount > maximumReferences ||
        !sha(value.rootSha256) || !sha(value.prefixSha256) || value.payloadSha256 !== digest(compact(value.payload))) {
      fail('PRIVATE_LINK_ARTIFACT_ENVELOPE_INVALID');
    }
    const slots = aggregateSlots(value.payload);
    Object.assign(state, { aggregate: true, nodes: 0 });
    let references = 0;
    const deferred = [];
    const result = await walker(state)(value.payload, async (entry, parent, key, owner) => {
      if (slots.has(memberPath(key, owner))) {
        completionReference(entry); countReference(state); references++;
        deferred.push({ reference: entry, path: memberPath(key, owner) });
        return entry;
      }
      if (entry.kind === completionReferenceKind || entry.kind === localPrefixKind || entry.kind === completionTemplateKind ||
          entry.kind === envelopeKind || entry.kind === recoveryContentKind) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_SCOPE');
      if (!referenceKinds.has(entry.kind)) return undefined;
      const type = eligible(parent, key, owner);
      if (!type || type.kind !== entry.kind) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_SCOPE');
      countReference(state); references++;
      return readContent(entry, type, state);
    });
    if (references !== value.referenceCount || deferred.length !== slots.size) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_COUNT_CHANGED');
    const prefix = freeze(aggregatePrefix(result));
    if (digestJson(prefix) !== value.prefixSha256) fail('PRIVATE_LINK_ARTIFACT_LOCAL_PREFIX_CHANGED');
    const aggregate = { prefix, prefixSha256: value.prefixSha256 };
    for (const item of deferred) {
      const path = JSON.parse(item.path), leaf = path.pop();
      let parent = result;
      for (const key of path) parent = parent[key];
      parent[leaf] = await readCompletion(item.reference, aggregate, state);
    }
    if (digestJson(result) !== value.rootSha256) fail('PRIVATE_LINK_ARTIFACT_AGGREGATE_CONTENT_CHANGED');
    return result;
  };
  return {
    load: async (directory, name, optional = false) => {
      const value = await read(directory, name, optional);
      return value === null ? null : decode(value);
    },
    immutable: async (directory, name, value) => immutable(directory, name, await encode(value)),
    update: async (directory, name, value) => update(directory, name, await encode(value)),
  };
}
async function store() {
  return createPrivateLinkArtifactStore({ root: await privateDirectory('infrastructure/arm/telemetry/.operator-private') });
}
export async function loadPrivateLinkArtifact(directory, name, optional = false) {
  return (await store()).load(directory, name, optional);
}
export async function savePrivateLinkArtifact(directory, name, value) {
  return (await store()).immutable(directory, name, value);
}
export async function updatePrivateLinkArtifact(directory, name, value) {
  return (await store()).update(directory, name, value);
}
