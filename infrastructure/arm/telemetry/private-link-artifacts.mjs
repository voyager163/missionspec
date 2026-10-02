import { isDeepStrictEqual } from 'node:util';
import { closed, digest, digestJson, fail } from './definition.mjs';
import { PRIVATE_LINK_CONTROL_STAGES } from './private-link.mjs';
import { load, save, saveImmutable, privateDirectory, MAX_PRIVATE_ARTIFACT_BYTES } from './controller.mjs';

const envelopeKind = 'private-link-artifact-envelope';
const referenceKind = 'private-link-control-evidence-reference';
const candidateReferenceKind = 'private-link-receiver-candidate-reference';
const owners = new Set(['private-link-runtime-completion', 'private-link-disabled-receiver',
  'private-link-reconciled-disabled-receiver', 'private-link-receiver-create-intent', 'private-link-window-intent']);
const maximumReferences = 64, maximumDistinctReferences = 8, maximumDepth = 128, maximumNodes = 4 * 1024 * 1024;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const evidenceName = sha => `private-link-evidence-${sha}.json`;
const candidateName = sha => `private-link-candidate-${sha}.json`;
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);

function compact(value) {
  const bytes = JSON.stringify(value) + '\n';
  if (Buffer.byteLength(bytes) > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_LINK_ARTIFACT_TOO_LARGE');
  return bytes;
}
function evidenceShape(value) {
  closed(value, ['version', 'kind', 'planSha256', 'originSha256', 'records',
    ...(value?.version === 2 ? ['externalAdoption'] : [])]);
  const stages = PRIVATE_LINK_CONTROL_STAGES.slice(0, PRIVATE_LINK_CONTROL_STAGES.indexOf('assign-queue-role') + 1);
  if (![1, 2].includes(value.version) || value.kind !== 'reviewed-private-link-control-chain' ||
      !sha(value.planSha256) || !sha(value.originSha256) || !Array.isArray(value.records) ||
      value.records.length !== stages.length || value.records.some((record, index) => record?.stage !== stages[index])) {
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
const referenceTypes = {
  controlEvidence: { kind: referenceKind, hashField: 'evidenceSha256', name: evidenceName, verify: evidenceShape },
  candidate: { kind: candidateReferenceKind, hashField: 'candidateSha256', name: candidateName, verify: candidateShape },
};
function referenceShape(value, type) {
  closed(value, ['version', 'kind', type.hashField, 'bytes']);
  if (value.version !== 1 || value.kind !== type.kind || !sha(value[type.hashField]) ||
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
  return async function walk(value, visit, parent = null, key = null, depth = 0) {
    if (++nodes > maximumNodes || depth > maximumDepth) fail('PRIVATE_LINK_ARTIFACT_STRUCTURE_LIMIT');
    if (value === null || ['string', 'boolean'].includes(typeof value) ||
        typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value !== 'object' || ancestors.has(value)) fail('PRIVATE_LINK_ARTIFACT_JSON_REQUIRED');
    const replacement = await visit(value, parent, key);
    if (replacement !== undefined) return replacement;
    ancestors.add(value);
    try {
      if (Array.isArray(value)) {
        const result = [];
        for (const entry of value) result.push(await walk(entry, visit, value, null, depth + 1));
        return result;
      }
      if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('PRIVATE_LINK_ARTIFACT_JSON_REQUIRED');
      const entries = [];
      for (const [name, entry] of Object.entries(value)) entries.push([name, await walk(entry, visit, value, name, depth + 1)]);
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
    if ([referenceKind, candidateReferenceKind, envelopeKind].includes(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
    ancestors.add(entry);
    try { for (const child of Object.values(entry)) visit(child, depth + 1); }
    finally { ancestors.delete(entry); }
  }
  visit(value, 0);
}
function eligible(parent, key) {
  return owners.has(parent?.kind) && Object.hasOwn(referenceTypes, key) ? referenceTypes[key] : null;
}

// Ports are trusted internal test dependencies, never artifact-supplied options.
export function createPrivateLinkArtifactStore({ root, read = load, immutable = saveImmutable, update = save }) {
  if (typeof root !== 'string') fail('PRIVATE_LINK_ARTIFACT_STORE_REQUIRED');
  const readContent = async (reference, type) => {
    referenceShape(reference, type);
    const value = await read(root, type.name(reference[type.hashField]));
    type.verify(value);
    await noReferences(value);
    if (Buffer.byteLength(compact(value)) !== reference.bytes ||
        digestJson(value) !== reference[type.hashField]) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
    return value;
  };
  const encode = async value => {
    let references = 0, evidenceBytes = 0;
    const written = new Set();
    const payload = await walker()(value, async (entry, parent, key) => {
      if ([referenceKind, candidateReferenceKind, envelopeKind].includes(entry.kind)) fail('PRIVATE_LINK_ARTIFACT_ALREADY_ENCODED');
      const type = eligible(parent, key);
      if (!type) return undefined;
      type.verify(entry);
      if (++references > maximumReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
      const bytes = compact(entry), snapshot = JSON.parse(bytes);
      await noReferences(snapshot);
      const hash = digestJson(snapshot), name = type.name(hash);
      const reference = { version: 1, kind: type.kind, [type.hashField]: hash, bytes: Buffer.byteLength(bytes) };
      if (!written.has(name)) {
        if (written.size >= maximumDistinctReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
        evidenceBytes += reference.bytes;
        if (evidenceBytes > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_BYTES_LIMIT');
        try { await immutable(root, name, bytes); }
        catch (error) {
          if (error.code !== 'EEXIST') throw error;
          if (!isDeepStrictEqual(await readContent(reference, type), snapshot)) fail('PRIVATE_LINK_ARTIFACT_CONTENT_CHANGED');
        }
        written.add(name);
      }
      return reference;
    });
    if (!references) return compact(payload);
    const bytes = compact(payload);
    return compact({ version: 1, kind: envelopeKind, referenceCount: references, payloadSha256: digest(bytes), payload });
  };
  const decode = async value => {
    if (!isObject(value) || value.kind !== envelopeKind) {
      await noReferences(value);
      return value;
    }
    closed(value, ['version', 'kind', 'referenceCount', 'payloadSha256', 'payload']);
    if (value.version !== 1 || !Number.isSafeInteger(value.referenceCount) || value.referenceCount < 1 ||
        value.referenceCount > maximumReferences || !sha(value.payloadSha256) ||
        digest(compact(value.payload)) !== value.payloadSha256) fail('PRIVATE_LINK_ARTIFACT_ENVELOPE_INVALID');
    let references = 0, evidenceBytes = 0;
    const loaded = new Map();
    const result = await walker()(value.payload, async (entry, parent, key) => {
      if (entry.kind === envelopeKind) fail('PRIVATE_LINK_ARTIFACT_NESTED_REFERENCE');
      if (![referenceKind, candidateReferenceKind].includes(entry.kind)) return undefined;
      const type = eligible(parent, key);
      if (!type || type.kind !== entry.kind) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_SCOPE');
      referenceShape(entry, type);
      const name = type.name(entry[type.hashField]);
      if (++references > maximumReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
      if (loaded.has(name)) {
        const prior = loaded.get(name);
        if (prior.bytes !== entry.bytes) fail('PRIVATE_LINK_ARTIFACT_EVIDENCE_CHANGED');
        return prior.value;
      }
      if (loaded.size >= maximumDistinctReferences) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_LIMIT');
      evidenceBytes += entry.bytes;
      if (evidenceBytes > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_BYTES_LIMIT');
      // Identical blocks share an immutable, fully loaded object within this
      // one read only. Semantic validation still belongs to the caller.
      const content = freeze(await readContent(entry, type));
      loaded.set(name, { bytes: entry.bytes, value: content });
      return content;
    });
    if (references !== value.referenceCount) fail('PRIVATE_LINK_ARTIFACT_REFERENCE_COUNT_CHANGED');
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
