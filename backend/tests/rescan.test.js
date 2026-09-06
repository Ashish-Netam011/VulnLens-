import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareScans, buildComparisonDetail } from '../src/services/rescanService.js';

function makeScan(findings) {
  return { findings };
}

test('compareScans classifies resolved/remaining/new', () => {
  const prev = makeScan([
    { comparisonKey: 'a:1', title: 'A' },
    { comparisonKey: 'b:2', title: 'B' },
    { comparisonKey: 'c:3', title: 'C' },
  ]);
  const curr = makeScan([
    { comparisonKey: 'b:2', title: 'B' }, // remaining
    { comparisonKey: 'd:40', title: 'D' }, // new
  ]);
  const result = compareScans(prev, curr);
  assert.deepEqual(result, { resolved: 2, remaining: 1, new: 1 });
});

test('buildComparisonDetail returns per-finding status', () => {
  const prev = makeScan([{ comparisonKey: 'a:1', title: 'A' }, { comparisonKey: 'b:2', title: 'B' }]);
  const curr = makeScan([{ comparisonKey: 'b:2', title: 'B' }, { comparisonKey: 'c:3', title: 'C' }]);
  const detail = buildComparisonDetail(prev, curr);
  assert.equal(detail.counts.resolved, 1);
  assert.equal(detail.counts.remaining, 1);
  assert.equal(detail.counts.new, 1);
  assert.equal(detail.remaining[0].status, 'remaining');
  assert.equal(detail.resolved[0].status, 'resolved');
  assert.equal(detail.newlyIntroduced[0].status, 'new');
});

test('identical scans produce zero deltas', () => {
  const findings = [{ comparisonKey: 'a:1', title: 'A' }];
  const result = compareScans(makeScan(findings), makeScan(findings));
  assert.deepEqual(result, { resolved: 0, remaining: 1, new: 0 });
});