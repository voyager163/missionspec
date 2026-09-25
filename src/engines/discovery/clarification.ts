import { parseId, type StableId } from '../../kernel/identifiers.js';
import { parseDigest, type ContentDigest } from '../../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../../kernel/validation.js';

export interface RevisionBoundQuestion {
  readonly id: StableId<'question'>;
  readonly question: string;
  readonly blocking: boolean;
  readonly artifactRevision: ContentDigest;
  readonly response: null | { readonly answer: string; readonly source: 'user' | 'proposed-assumption' };
}

export function parseRevisionBoundQuestion(value: unknown): RevisionBoundQuestion {
  const input = record(value, 'question', ['id', 'question', 'blocking', 'artifactRevision', 'response']);
  if (typeof input.blocking !== 'boolean') throw new ContractError('question.blocking', 'expected an explicit boolean');
  const response = input.response === null ? null : record(input.response, 'question.response', ['answer', 'source']);
  return Object.freeze({
    id: parseId('question', input.id), question: text(input.question, 'question'),
    blocking: input.blocking, artifactRevision: parseDigest(input.artifactRevision),
    response: response === null ? null : Object.freeze({
      answer: text(response.answer, 'answer'),
      source: oneOf(response.source, ['user', 'proposed-assumption'], 'answer.source'),
    }),
  });
}

/** Prioritization and freshness, not a claim that a model asked the right question. */
export function assessClarifications(
  values: readonly RevisionBoundQuestion[],
  revision: ContentDigest,
  alreadyAsked: readonly StableId<'question'>[] = [],
) {
  const current = parseDigest(revision);
  const questions = array(values, 'questions', parseRevisionBoundQuestion);
  unique(questions.map((question) => question.id), 'questions');
  if (questions.length > 128) throw new ContractError('questions', 'at most 128 tracked questions are supported');
  const asked = new Set(unique(array(alreadyAsked, 'alreadyAsked', (id) => parseId('question', id)), 'alreadyAsked'));
  if ([...asked].some((id) => !questions.some((question) => question.id === id))) {
    throw new ContractError('alreadyAsked', 'asked identity must belong to the current question set');
  }
  const assessments = questions.map((question) => ({
    question,
    state: question.artifactRevision !== current ? 'stale' as const
      : question.response === null ? 'unanswered' as const
        : question.response.source === 'proposed-assumption' ? 'assumed' as const : 'answered' as const,
  }));
  const unresolved = assessments.filter((entry) => entry.state !== 'answered');
  const consequential = unresolved.filter((entry) => entry.question.blocking);
  const candidates = consequential.length === 0 ? unresolved : consequential;
  const next = candidates.find((entry) => !asked.has(entry.question.id));
  return Object.freeze({
    artifactRevision: current,
    assessments: Object.freeze(assessments),
    blockers: Object.freeze(consequential.map((entry) => entry.question.id)),
    assumptions: Object.freeze(assessments.filter((entry) => entry.state === 'assumed').map((entry) => entry.question.id)),
    next: next === undefined
      ? Object.freeze({ state: unresolved.length === 0 ? 'resolved' as const : 'waiting-for-input' as const })
      : Object.freeze({ state: 'question' as const, question: next.question }),
    authorityIssued: false as const,
  });
}
