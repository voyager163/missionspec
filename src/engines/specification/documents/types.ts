import type {
  ArtifactId, ChangeId, CheckId, ProjectPath, RequirementId, ScenarioId, TaskId,
} from '../../../kernel/identifiers.js';
import type { ContentDigest } from '../../../kernel/revisions.js';

export const DOCUMENT_KINDS = Object.freeze([
  'proposal', 'specs', 'baseline', 'design', 'tasks', 'verification', 'discovery', 'principles',
] as const);
export type DocumentKind = (typeof DOCUMENT_KINDS)[number];

export interface SourceLocation {
  readonly path: ProjectPath | null;
  readonly line: number;
  readonly column: number;
  readonly offset: number;
}

export type DocumentDiagnosticCode =
  | 'invalid-source' | 'invalid-path' | 'missing-frontmatter' | 'invalid-yaml'
  | 'invalid-metadata' | 'unsupported-version' | 'invalid-title' | 'invalid-section'
  | 'duplicate-section' | 'missing-section' | 'empty-section' | 'invalid-declaration'
  | 'missing-declaration-metadata' | 'unexpected-metadata' | 'empty-declaration'
  | 'duplicate-identity' | 'invalid-reference' | 'removed-reference'
  | 'mixed-changes' | 'task-cycle';

export interface DocumentDiagnostic {
  readonly code: DocumentDiagnosticCode;
  readonly message: string;
  readonly location: SourceLocation;
}

export interface DocumentSection {
  readonly name: string;
  readonly content: string;
  readonly location: SourceLocation;
}

interface DeclarationBase {
  readonly title: string;
  readonly prose: string;
  readonly location: SourceLocation;
  readonly intentRevision: ContentDigest;
}

export interface RequirementDeclaration extends DeclarationBase {
  readonly kind: 'requirement';
  readonly id: RequirementId;
  readonly operation: 'add' | 'modify' | 'remove' | 'retain';
}

export interface ScenarioDeclaration extends DeclarationBase {
  readonly kind: 'scenario';
  readonly id: ScenarioId;
  readonly operation: 'add' | 'modify' | 'remove' | 'retain';
  readonly requirement: RequirementId;
}

export interface TaskDeclaration extends DeclarationBase {
  readonly kind: 'task';
  readonly id: TaskId;
  readonly progressClaim: 'unchecked' | 'checked';
  readonly dependsOn: readonly TaskId[];
  readonly requirements: readonly RequirementId[];
  readonly scenarios: readonly ScenarioId[];
  readonly checks: readonly CheckId[];
  readonly writeScope: readonly ProjectPath[];
}

export interface CheckDeclaration extends DeclarationBase {
  readonly kind: 'check';
  readonly id: CheckId;
  readonly method: 'executed' | 'static-inspection' | 'agent-review';
  readonly requirements: readonly RequirementId[];
  readonly scenarios: readonly ScenarioId[];
}

export type DocumentDeclaration =
  | RequirementDeclaration | ScenarioDeclaration | TaskDeclaration | CheckDeclaration;

export interface MarkdownDocument {
  readonly schemaVersion: 1;
  readonly id: ArtifactId;
  readonly kind: DocumentKind;
  readonly checks?: 'verification.md';
  readonly changeId: ChangeId | null;
  readonly path: ProjectPath;
  readonly title: string;
  readonly source: string;
  readonly rawRevision: ContentDigest;
  readonly intentRevision: ContentDigest;
  readonly sections: readonly DocumentSection[];
  readonly declarations: readonly DocumentDeclaration[];
}

export type DocumentParseResult =
  | { readonly state: 'parsed'; readonly document: MarkdownDocument }
  | { readonly state: 'invalid'; readonly diagnostics: readonly DocumentDiagnostic[] };

export interface MarkdownSource {
  readonly path: ProjectPath;
  readonly content: string;
}

export type DocumentSetResult =
  | { readonly state: 'valid'; readonly documents: readonly MarkdownDocument[] }
  | {
    readonly state: 'invalid';
    readonly parsedDocuments: readonly MarkdownDocument[];
    readonly diagnostics: readonly DocumentDiagnostic[];
  };
