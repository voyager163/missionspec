import { array } from '../../../kernel/validation.js';
import { parseMarkdownDocument } from './parser.js';
import type {
  DocumentDeclaration, DocumentDiagnostic, DocumentSetResult, MarkdownDocument, SourceLocation, TaskDeclaration,
} from './types.js';

export function parseMarkdownSet(value: unknown): DocumentSetResult {
  const documents: MarkdownDocument[] = [];
  const diagnostics: DocumentDiagnostic[] = [];
  const report = (
    code: DocumentDiagnostic['code'], message: string, location: SourceLocation,
  ): void => {
    diagnostics.push(Object.freeze({ code, message, location }));
  };
  let entries;
  try {
    entries = array(value, 'documents', (entry) => entry);
  } catch {
    return Object.freeze({
      state: 'invalid', parsedDocuments: Object.freeze([]),
      diagnostics: Object.freeze([Object.freeze({
        code: 'invalid-source', message: 'Supply a dense array of Markdown sources.',
        location: Object.freeze({ path: null, line: 1, column: 1, offset: 0 }),
      })]),
    });
  }
  for (const entry of entries) {
    const result = parseMarkdownDocument(entry);
    if (result.state === 'parsed') documents.push(result.document);
    else diagnostics.push(...result.diagnostics);
  }
  const declarations = new Map<string, DocumentDeclaration>();
  const documentIds = new Set<string>();
  const paths = new Set<string>();
  let changeId: MarkdownDocument['changeId'] = null;
  for (const document of documents) {
    const origin = Object.freeze({ path: document.path, line: 1, column: 1, offset: 0 });
    if (documentIds.has(document.id) || paths.has(document.path)) {
      report('duplicate-identity', 'Document identities and paths must be unique in the supplied set.', origin);
    }
    documentIds.add(document.id);
    paths.add(document.path);
    if (document.checks === 'verification.md') {
      const target = `${document.path.slice(0, document.path.lastIndexOf('/') + 1)}verification.md`;
      if (!documents.some((candidate) => candidate.kind === 'verification' && candidate.path === target && candidate.changeId === document.changeId)) {
        report('invalid-reference', 'Explicit external checks require the sibling verification document in the supplied set.', origin);
      }
    }
    if (document.changeId !== null) {
      if (changeId !== null && changeId !== document.changeId) {
        report('mixed-changes', 'A document set must refer to one change, plus optional project principles.', origin);
      }
      changeId ??= document.changeId;
    }
    for (const declaration of document.declarations) {
      if (declarations.has(declaration.id)) {
        report('duplicate-identity', 'Every fact must have exactly one canonical definition across the document set.', declaration.location);
      } else declarations.set(declaration.id, declaration);
    }
  }
  const reference = (
    id: string, kind: DocumentDeclaration['kind'], declaration: DocumentDeclaration, allowRemoved = false,
  ): void => {
    const target = declarations.get(id);
    if (target === undefined || target.kind !== kind) {
      report('invalid-reference', 'A typed reference has no matching definition in the supplied set.', declaration.location);
    } else if ('operation' in target && target.operation === 'remove' && !allowRemoved) {
      report('removed-reference', 'An active fact must not depend on a removed definition.', declaration.location);
    }
  };
  const tasks: TaskDeclaration[] = [];
  for (const declaration of declarations.values()) {
    if (declaration.kind === 'scenario') {
      reference(declaration.requirement, 'requirement', declaration, declaration.operation === 'remove');
    }
    if (declaration.kind === 'task' || declaration.kind === 'check') {
      for (const id of declaration.requirements) reference(id, 'requirement', declaration);
      for (const id of declaration.scenarios) reference(id, 'scenario', declaration);
    }
    if (declaration.kind === 'task') {
      for (const id of declaration.dependsOn) reference(id, 'task', declaration);
      for (const id of declaration.checks) reference(id, 'check', declaration);
      tasks.push(declaration);
    }
  }
  const taskIds = new Set(tasks.map((task) => task.id));
  const remaining = new Map(tasks.map((task) => [
    task.id, task.dependsOn.filter((dependency) => taskIds.has(dependency)).length,
  ]));
  const dependents = new Map<string, TaskDeclaration[]>();
  for (const task of tasks) {
    for (const dependency of task.dependsOn) {
      const list = dependents.get(dependency) ?? [];
      list.push(task);
      dependents.set(dependency, list);
    }
  }
  const ready = tasks.filter((task) => remaining.get(task.id) === 0);
  for (let index = 0; index < ready.length; index += 1) {
    const task = ready[index];
    if (task === undefined) continue;
    for (const dependent of dependents.get(task.id) ?? []) {
      const count = remaining.get(dependent.id);
      if (count === undefined) continue;
      remaining.set(dependent.id, count - 1);
      if (count === 1) ready.push(dependent);
    }
  }
  if (ready.length !== tasks.length) {
    const cyclic = tasks.find((task) => (remaining.get(task.id) ?? 0) > 0);
    if (cyclic !== undefined) report('task-cycle', 'Task dependencies contain a cycle.', cyclic.location);
  }
  if (diagnostics.length > 0) {
    return Object.freeze({
      state: 'invalid', parsedDocuments: Object.freeze(documents), diagnostics: Object.freeze(diagnostics),
    });
  }
  return Object.freeze({ state: 'valid', documents: Object.freeze(documents) });
}
