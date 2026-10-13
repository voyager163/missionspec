import { isAlias, parseDocument, visit } from 'yaml';

export class MetadataSyntaxError extends Error {
  readonly offset: number;

  constructor(offset = 0) {
    super('Invalid declarative YAML.');
    this.offset = offset;
  }
}

export function readMetadata(source: string): unknown {
  let document;
  try {
    document = parseDocument(source, { strict: true, uniqueKeys: true, version: '1.2' });
  } catch {
    throw new MetadataSyntaxError();
  }
  const problem = document.errors[0] ?? document.warnings[0];
  if (problem !== undefined) {
    throw new MetadataSyntaxError(problem.pos[0]);
  }
  visit(document, {
    Node(_key, node) {
      if (isAlias(node) || ('anchor' in node && node.anchor) || ('tag' in node && node.tag)) {
        throw new MetadataSyntaxError(node.range?.[0] ?? 0);
      }
    },
  });
  try {
    const value: unknown = document.toJS({ maxAliasCount: 0 });
    return value;
  } catch {
    throw new MetadataSyntaxError();
  }
}
