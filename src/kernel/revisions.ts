import { createHash } from 'node:crypto';
import { parseId, type ChangeId, type WorkspaceId } from './identifiers.js';
import { ContractError, record } from './validation.js';

declare const digestBrand: unique symbol;
export type ContentDigest = string & { readonly [digestBrand]: true };

export function parseDigest(value: unknown): ContentDigest {
  if (typeof value !== 'string' || !/^sha256:[a-f0-9]{64}$/u.test(value)) {
    throw new ContractError('digest', 'expected a lowercase sha256 digest');
  }
  return value as ContentDigest;
}

export function digestContent(content: string | Uint8Array): ContentDigest {
  if (typeof content !== 'string' && !(content instanceof Uint8Array)) {
    throw new ContractError('content', 'expected UTF-8 text or bytes');
  }
  return parseDigest(`sha256:${createHash('sha256').update(content).digest('hex')}`);
}

export interface WorkspaceBinding {
  readonly workspaceId: WorkspaceId;
  readonly rootDigest: ContentDigest;
}

export function parseWorkspaceBinding(value: unknown): WorkspaceBinding {
  const input = record(value, 'workspace', ['workspaceId', 'rootDigest']);
  return Object.freeze({
    workspaceId: parseId('workspace', input.workspaceId),
    rootDigest: parseDigest(input.rootDigest),
  });
}

export function sameWorkspaceBinding(left: WorkspaceBinding, right: WorkspaceBinding): boolean {
  const a = parseWorkspaceBinding(left);
  const b = parseWorkspaceBinding(right);
  return a.workspaceId === b.workspaceId && a.rootDigest === b.rootDigest;
}

export interface RevisionBinding {
  readonly workspace: WorkspaceBinding;
  readonly changeId: ChangeId;
  readonly specification: ContentDigest;
  readonly tasks: ContentDigest;
  readonly workflow: ContentDigest;
  readonly effects: ContentDigest;
  readonly source: ContentDigest;
}

export function parseRevisionBinding(value: unknown): RevisionBinding {
  const input = record(value, 'revisions', [
    'workspace', 'changeId', 'specification', 'tasks', 'workflow', 'effects', 'source',
  ]);
  return Object.freeze({
    workspace: parseWorkspaceBinding(input.workspace),
    changeId: parseId('change', input.changeId),
    specification: parseDigest(input.specification),
    tasks: parseDigest(input.tasks),
    workflow: parseDigest(input.workflow),
    effects: parseDigest(input.effects),
    source: parseDigest(input.source),
  });
}

export function sameRevisionBinding(left: RevisionBinding, right: RevisionBinding): boolean {
  const a = parseRevisionBinding(left);
  const b = parseRevisionBinding(right);
  return sameWorkspaceBinding(a.workspace, b.workspace) &&
    a.changeId === b.changeId &&
    a.specification === b.specification &&
    a.tasks === b.tasks &&
    a.workflow === b.workflow &&
    a.effects === b.effects &&
    a.source === b.source;
}

export type ReviewBinding =
  | { readonly kind: 'change'; readonly revisions: RevisionBinding }
  | { readonly kind: 'review'; readonly revisions: RevisionBinding; readonly subject: ContentDigest; readonly effects: ContentDigest }
  | { readonly kind: 'project'; readonly workspace: WorkspaceBinding; readonly revision: ContentDigest; readonly effects: ContentDigest };

export function parseReviewBinding(value: unknown): ReviewBinding {
  const tag = record(value, 'binding', ['kind', 'workspace', 'revisions', 'revision', 'effects', 'subject']);
  if (tag.kind === 'change') {
    const input = record(value, 'binding', ['kind', 'revisions']);
    return Object.freeze({ kind: 'change', revisions: parseRevisionBinding(input.revisions) });
  }
  if (tag.kind === 'review') {
    const input = record(value, 'binding', ['kind', 'revisions', 'subject', 'effects']);
    return Object.freeze({
      kind: 'review', revisions: parseRevisionBinding(input.revisions),
      subject: parseDigest(input.subject), effects: parseDigest(input.effects),
    });
  }
  if (tag.kind === 'project') {
    const input = record(value, 'binding', ['kind', 'workspace', 'revision', 'effects']);
    return Object.freeze({
      kind: 'project',
      workspace: parseWorkspaceBinding(input.workspace),
      revision: parseDigest(input.revision),
      effects: parseDigest(input.effects),
    });
  }
  throw new ContractError('binding.kind', 'expected change, review or project');
}
