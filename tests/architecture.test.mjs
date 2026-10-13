import assert from 'node:assert/strict';
import test from 'node:test';
import { cycleProblems, importProblem, sourceImports } from '../scripts/check-architecture.mjs';

test('engines may import their own code, shared ports and explicit public contracts', () => {
  for (const target of ['./contracts.js', '../../kernel/ids.js', '../../ports/store.js', '../specification/contracts.js']) {
    assert.equal(importProblem('engines/planning/index.ts', target), undefined);
  }
  assert.equal(importProblem('engines/specification/codec.ts', 'yaml'), undefined);
});

test('engines and transports cannot bypass private boundaries', () => {
  for (const [source, target] of [
    ['engines/planning/index.ts', '../../adapters/filesystem/read.js'],
    ['engines/planning/index.ts', '../../cli/main.js'],
    ['engines/planning/index.ts', '../specification/private.js'],
    ['cli/main.ts', '../engines/planning/private.js'],
    ['kernel/ids.ts', '../engines/planning/contracts.js'],
    ['engines/planning/index.ts', 'node:fs'],
    ['engines/context/index.ts', './contracts.js']
  ]) assert.notEqual(importProblem(source, target), undefined, `${source} -> ${target}`);
});

test('parser inspects imports, re-exports and dynamic imports without executing source', () => {
  const { imports, unsupported } = sourceImports(`
    import type { A } from './a.js';
    export { value } from './b.js';
    type B = import('./types.js').B;
    const c = import('./c.js');
    const d = require('./d.js');
    import e = require('./e.js');
    const unknown = import(variable);
  `, 'example.ts');
  assert.deepEqual(imports, ['./a.js', './b.js', './types.js', './c.js', './d.js', './e.js']);
  assert.equal(unsupported.length, 1);
});

test('engine dependency cycles are rejected, while shared dependencies are valid', () => {
  assert.deepEqual(cycleProblems(new Map([['planning', new Set(['specification'])]])), []);
  assert.match(cycleProblems(new Map([
    ['planning', new Set(['specification'])],
    ['specification', new Set(['planning'])]
  ])).join('\n'), /Cyclic engine dependency/);
});
