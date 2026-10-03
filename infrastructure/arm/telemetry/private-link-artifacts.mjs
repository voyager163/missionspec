import { isDeepStrictEqual } from 'node:util';
import { closed, digest, digestJson, fail } from './definition.mjs';
import { PRIVATE_LINK_CONTROL_STAGES } from './private-link.mjs';
import { load, save, saveImmutable, privateDirectory, MAX_PRIVATE_ARTIFACT_BYTES } from './controller.mjs';

const envelopeKind = 'private-link-artifact-envelope';
const referenceKind = 'private-link-control-evidence-reference';
const candidateReferenceKind = 'private-link-receiver-candidate-reference';
const recoveryReferenceKind = 'private-link-continued-recovery-reference';
const recoveryContentKind = 'private-link-continued-recovery-content';
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
const reservedKinds = new Set([envelopeKind, referenceKind, candidateReferenceKind, recoveryReferenceKind, recoveryContentKind]);

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
function restoreRecovery(value, expectedSha256) {
  closed(value, ['version', 'kind', 'recordSha256', 'payloadSha256', 'payload']);
  if (value.version !== 1 || value.kind !== recoveryContentKind || value.recordSha256 !== expectedSha256 ||
      !sha(value.payloadSha256) || digest(compact(value.payload)) !== value.payloadSha256) {
    fail('PRIVATE_LINK_ARTIFACT_RECOVERY_CONTENT_CHANGED');
  }
  closed(value.payload, recoveryKeys);
  if (value.payload.phase !== null || value.payload.preflight !== null ||
      !isObject(value.payload.recovery?.original)) fail('PRIVATE_LINK_ARTIFACT_RECOVERY_PROJECTION_INVALID');
  noReferences(value.payload);
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
function walker() {
  let nodes = 0;
  const ancestors = new Set();
  return async function walk(value, visit, parent = null, key = null, depth = 0, owner = null) {
    if (++nodes > maximumNodes || depth > maximumDepth) fail('PRIVATE_LINK_ARTIFACT_STRUCTURE_LIMIT');
    if (value === null || ['string', 'boolean'].includes(typeof value) ||
        typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value !== 'object' || ancestors.has(value)) fail('PRIVATE_LINK_ARTIFACT_JSON_REQUIRED');
    const replacement = await visit(value, parent, key, owner);
    if (replacement !== undefined) return replacement;
    ancestors.add(value);
    try {
      if (Array.isArray(value)) {
        const result = [];
        for (const [index, entry] of value.entries()) result.push(await walk(entry, visit, value, index, depth + 1, { parent, key }));
        return result;
      }
      if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('PRIVATE_LINK_ARTIFACT_JSON_REQUIRED');
      const entries = [];
      for (const [name, entry] of Object.entries(value)) entries.push([name, await walk(entry, visit, value, name, depth + 1, { parent, key })]);
      return Object.fromEntries(entries);
    } finally { ancestors.delete(value); }
  };
}
function noReferences(value) {
  let nodes = 0;
  const ancestors = new Set();
  function visit(entry, depth) {
    if (++nodes > maximumNodes || depth > maximumDepth) fail('PRIVATE_LINK_ARTIFACT_STRUCTURE_LIMIT');
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

// Ports are trusted internal test dependencies, never artifact-supplied options.
export function createPrivateLinkArtifactStore({ root, read = load, immutable = saveImmutable, update = save }) {
  if (typeof root !== 'string') fail('PRIVATE_LINK_ARTIFACT_STORE_REQUIRED');
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
      if (type === recoveryType) value = restoreRecovery(stored, reference.recordSha256);
      else if (type === referenceTypes.controlEvidence && reference.version === 2) {
        if (stored?.kind !== envelopeKind || stored.version !== 2) fail('PRIVATE_LINK_ARTIFACT_ENVELOPE_INVALID');
        value = await decodeEnvelope(stored, state, true);
      } else { noReferences(stored); value = stored; }
      type.verify(value);
      if (digestJson(value) !== reference[type.hashField]) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
      value = freeze(value);
      state.loaded.set(name, { bytes: reference.bytes, value });
      return value;
    } finally { state.active.delete(name); }
  };
  const encodePayload = async (value, state, recoveryOnly = false) => {
    let references = 0, modern = false;
    const payload = await walker()(value, async (entry, parent, key, owner) => {
      if (reservedKinds.has(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_ALREADY_ENCODED');
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
        const bytes = type === recoveryType ? compact(projectRecovery(snapshot, hash)) :
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
    if (!references) return compact(payload);
    const bytes = compact(payload);
    return compact({ version: modern ? 2 : 1, kind: envelopeKind, referenceCount: references, payloadSha256: digest(bytes), payload });
  };
  const encode = value => encodePayload(value, { references: 0, bytes: 0, written: new Map() });
  const decodeEnvelope = async (value, state, recoveryOnly = false) => {
    closed(value, ['version', 'kind', 'referenceCount', 'payloadSha256', 'payload']);
    if (![1, 2].includes(value.version) || !Number.isSafeInteger(value.referenceCount) || value.referenceCount < 1 ||
        value.referenceCount > maximumReferences || !sha(value.payloadSha256) ||
        digest(compact(value.payload)) !== value.payloadSha256) fail('PRIVATE_LINK_ARTIFACT_ENVELOPE_INVALID');
    let references = 0;
    const result = await walker()(value.payload, async (entry, parent, key, owner) => {
      if ([envelopeKind, recoveryContentKind].includes(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
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
    return decodeEnvelope(value, { references: 0, bytes: 0, loaded: new Map(), active: new Set() });
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
