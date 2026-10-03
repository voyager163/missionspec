import assert from 'node:assert/strict';
import test from 'node:test';
import { assessClarifications, parseRevisionBoundQuestion } from '../dist/engines/discovery/contracts.js';
import { digestContent } from '../dist/kernel/revisions.js';

const revision = digestContent('Original current clarification fixture');
const question = (id, blocking = true, response = null) => ({
  id: `QST-${id}`, question: 'What behavior should the original example preserve?',
  blocking, artifactRevision: revision, response,
});

test('clarification selects one consequential question before low-impact preferences', () => {
  const values = [question('minor', false), question('scope'), question('acceptance')];
  const report = assessClarifications(values, revision);
  assert.equal(report.next.state, 'question');
  assert.equal(report.next.question.id, 'QST-scope');
  assert.deepEqual(report.blockers, ['QST-scope', 'QST-acceptance']);
  assert.equal(report.authorityIssued, false);
});

test('previously asked material questions stay unresolved without repeated automatic questioning', () => {
  const values = [question('minor', false), question('scope')];
  const report = assessClarifications(values, revision, ['QST-scope']);
  assert.deepEqual(report.next, { state: 'waiting-for-input' });
  assert.deepEqual(report.blockers, ['QST-scope']);
});

test('assumptions and stale user responses cannot clear material clarification', () => {
  const report = assessClarifications([
    question('assumption', true, { answer: 'Use the proposed default.', source: 'proposed-assumption' }),
    { ...question('old', true, { answer: 'Use the explicitly requested behavior.', source: 'user' }), artifactRevision: digestContent('prior intent') },
    question('answered', true, { answer: 'Use the explicitly requested behavior.', source: 'user' }),
  ], revision);
  assert.deepEqual(report.assessments.map((entry) => entry.state), ['assumed', 'stale', 'answered']);
  assert.deepEqual(report.blockers, ['QST-assumption', 'QST-old']);
  assert.deepEqual(report.assumptions, ['QST-assumption']);
});

test('minor assumptions are inspectable, while explicit current responses resolve without issuing authority', () => {
  const resolved = assessClarifications([question('scope', true, { answer: 'Preserve the example.', source: 'user' })], revision);
  assert.deepEqual(resolved.next, { state: 'resolved' });
  assert.deepEqual(resolved.blockers, []);
  assert.equal(resolved.authorityIssued, false);
  const minor = assessClarifications([question('minor', false, { answer: 'Use the default label.', source: 'proposed-assumption' })], revision);
  assert.deepEqual(minor.blockers, []);
  assert.deepEqual(minor.assumptions, ['QST-minor']);
});

test('clarification rejects duplicate IDs, unknown asked IDs and authority-shaped fields', () => {
  assert.throws(() => assessClarifications([question('scope'), question('scope')], revision));
  assert.throws(() => assessClarifications([question('scope')], revision, ['QST-absent']));
  assert.throws(() => parseRevisionBoundQuestion({ ...question('scope'), approved: true }));
});
