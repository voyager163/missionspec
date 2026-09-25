import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import type { MarkdownSource } from '../../engines/specification/contracts.js';
import { parseProjectPath, type ProjectPath } from '../../kernel/identifiers.js';
import type { ErrorCode } from '../../kernel/outcomes.js';
import { array, ContractError, unique } from '../../kernel/validation.js';

const fileLimit = 1_000_000;
const totalLimit = 8_000_000;

export class ArtifactReadError extends Error {
  readonly code: ErrorCode;
  readonly path: ProjectPath | null;

  constructor(code: ErrorCode, message: string, source: ProjectPath | null = null) {
    super(message);
    this.name = 'ArtifactReadError';
    this.code = code;
    this.path = source;
  }
}

async function checkedPath(root: string, relative: ProjectPath): Promise<string> {
  let current = root;
  const parts = relative.split('/');
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part === undefined) throw new ContractError('source.path', 'missing path segment');
    current = path.join(current, part);
    const info = await lstat(current, { bigint: true });
    if (info.isSymbolicLink() || (index < parts.length - 1 && !info.isDirectory())) {
      throw new ArtifactReadError('scope-exceeded', 'Artifact paths must not traverse symbolic links or non-directories.', relative);
    }
  }
  const resolved = await realpath(current);
  const distance = path.relative(root, resolved);
  if (distance === '..' || distance.startsWith(`..${path.sep}`) || path.isAbsolute(distance)) {
    throw new ArtifactReadError('scope-exceeded', 'Artifact path is outside the selected workspace.', relative);
  }
  return resolved;
}

export async function readMarkdownSources(rootPath: string, inputs: unknown): Promise<readonly MarkdownSource[]> {
  const paths = unique(array(inputs, 'sources', parseProjectPath, 1), 'sources');
  if (paths.length > 128) throw new ArtifactReadError('limit-reached', 'At most 128 explicitly selected documents can be read.');
  if (paths.some((source) => !source.endsWith('.md'))) {
    throw new ArtifactReadError('invalid-input', 'Select structured Markdown files with the .md extension.');
  }
  const root = await realpath(rootPath);
  if (!(await lstat(root)).isDirectory()) throw new ArtifactReadError('invalid-input', 'The workspace root must be a directory.');
  const sources: MarkdownSource[] = [];
  const identities = new Set<string>();
  let total = 0;
  for (const source of paths) {
    let handle;
    try {
      const resolved = await checkedPath(root, source);
      handle = await open(resolved, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const before = await handle.stat({ bigint: true });
      if (!before.isFile()) throw new ArtifactReadError('invalid-input', 'Artifact input is not a regular file.', source);
      if (before.size > BigInt(fileLimit)) throw new ArtifactReadError('limit-reached', 'Artifact byte limit exceeded.', source);
      const identity = `${before.dev}:${before.ino}`;
      if (identities.has(identity)) throw new ArtifactReadError('conflict', 'The same physical document was selected more than once.', source);
      identities.add(identity);
      const bytes = Buffer.alloc(fileLimit + 1);
      let length = 0;
      while (length < bytes.length) {
        const result = await handle.read(bytes, length, bytes.length - length, null);
        if (result.bytesRead === 0) break;
        length += result.bytesRead;
      }
      if (length > fileLimit) throw new ArtifactReadError('limit-reached', 'Artifact byte limit exceeded.', source);
      total += length;
      if (total > totalLimit) throw new ArtifactReadError('limit-reached', 'Document-set byte limit exceeded.');
      const after = await handle.stat({ bigint: true });
      const current = await lstat(await checkedPath(root, source), { bigint: true });
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
          before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
          current.dev !== after.dev || current.ino !== after.ino ||
          current.mtimeNs !== after.mtimeNs || current.size !== after.size) {
        throw new ArtifactReadError('stale-revision', 'Artifact changed during observation; retry from a stable source.', source);
      }
      let content: string;
      try {
        content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
      } catch {
        throw new ArtifactReadError('invalid-input', 'Artifact is not valid UTF-8.', source);
      }
      sources.push(Object.freeze({ path: source, content }));
    } catch (error) {
      if (error instanceof ArtifactReadError || error instanceof ContractError) throw error;
      const missing = typeof error === 'object' && error !== null && 'code' in error &&
        (error.code === 'ENOENT' || error.code === 'ENOTDIR');
      throw new ArtifactReadError(missing ? 'not-found' : 'persistence-failed', 'Unable to read the selected artifact safely.', source);
    } finally {
      if (handle !== undefined) {
        try {
          await handle.close();
        } catch {
          throw new ArtifactReadError('persistence-failed', 'Artifact read handle could not be closed.', source);
        }
      }
    }
  }
  return Object.freeze(sources);
}
