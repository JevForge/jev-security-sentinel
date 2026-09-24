import { describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { annotateFindings } from '../../src/decision/annotate.js';
import { applyGate } from '../../src/decision/policy.js';
import { loadBaselineFingerprints } from '../../src/collectors/baseline.js';
import { DEFAULT_POLICY } from '../../src/schemas/sentinel.js';
import type { RawFinding } from '../../src/collectors/common.js';
import { fingerprint } from '../../src/utils/fingerprint.js';

function raw(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    source: 'sarif',
    category: 'sast',
    severity: 'critical',
    title: 'SQL injection',
    rule_id: 'sql.inject',
    path: 'src/db.ts',
    start_line: 10,
    cve: null,
    exploitability: 'unknown',
    message: 'query',
    component: '',
    scanner_suppressed: false,
    ...overrides,
  };
}

describe('baseline / new_only gate mode', () => {
  it('loads fingerprints from several JSON shapes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'baseline-'));
    writeFileSync(join(dir, 'a.json'), JSON.stringify(['abcdefghijkl']));
    writeFileSync(join(dir, 'b.json'), JSON.stringify({ fingerprints: ['mnopqrstuvwx'] }));
    writeFileSync(
      join(dir, 'c.json'),
      JSON.stringify({ findings: [{ fingerprint: 'yz0123456789' }] }),
    );
    expect([...loadBaselineFingerprints(dir, 'a.json').fingerprints]).toContain('abcdefghijkl');
    expect([...loadBaselineFingerprints(dir, 'b.json').fingerprints]).toContain('mnopqrstuvwx');
    expect([...loadBaselineFingerprints(dir, 'c.json').fingerprints]).toContain('yz0123456789');
  });

  it('keeps baseline findings visible without raising the floor', () => {
    const known = fingerprint(['sarif', 'sql.inject', 'src/db.ts', 10, '', 'SQL injection']);
    const findings = annotateFindings({
      raw: [
        raw(),
        raw({
          title: 'New XSS',
          rule_id: 'xss.dom',
          path: 'src/ui.ts',
          start_line: 3,
          severity: 'high',
        }),
      ],
      policy: DEFAULT_POLICY,
      environment: 'production',
      component: 'api',
      gateScope: 'all',
      gateMode: 'new_only',
      baselineFingerprints: new Set([known]),
      changedPaths: null,
    });

    expect(findings[0]?.gate_effect).toBe('baseline');
    expect(findings[0]?.baseline_matched).toBe(true);
    expect(findings[1]?.gate_effect).toBe('blocking');
    expect(findings[1]?.baseline_matched).toBe(false);

    const outcome = applyGate({
      findings,
      policy: DEFAULT_POLICY,
      jev: {
        status: 'evaluated',
        decision: 'PASS',
        confidence: 0.9,
        explanation: 'ok',
        abstain: false,
      },
      minConfidence: 0.75,
      lowConfidencePolicy: 'fail',
      sourceErrorPolicy: 'fail',
      reviewMode: 'fail',
      sourceErrors: [],
      truncated: false,
      changedPathsUnknown: false,
    });

    expect(outcome.decision.decision).toBe('BLOCK');
    expect(outcome.decision.risk_summary.baseline).toBe(1);
    expect(outcome.decision.risk_summary.blocking).toBe(1);
    expect(outcome.decision.findings).toHaveLength(2);
    expect(outcome.decision.reason_codes).toContain('BASELINE_MATCHED');
    expect(outcome.decision.reason_codes).toContain('NEW_FINDINGS_ONLY');
    expect(outcome.decision.reason_codes).toContain('FINDINGS_PRESERVED');
  });

  it('passes when every finding matches the baseline', () => {
    const known = fingerprint(['sarif', 'sql.inject', 'src/db.ts', 10, '', 'SQL injection']);
    const findings = annotateFindings({
      raw: [raw()],
      policy: DEFAULT_POLICY,
      environment: 'production',
      component: 'api',
      gateScope: 'all',
      gateMode: 'new_only',
      baselineFingerprints: new Set([known]),
      changedPaths: null,
    });
    const outcome = applyGate({
      findings,
      policy: DEFAULT_POLICY,
      jev: {
        status: 'evaluated',
        decision: 'PASS',
        confidence: 0.95,
        explanation: 'baseline only',
        abstain: false,
      },
      minConfidence: 0.75,
      lowConfidencePolicy: 'fail',
      sourceErrorPolicy: 'fail',
      reviewMode: 'fail',
      sourceErrors: [],
      truncated: false,
      changedPathsUnknown: false,
    });
    expect(outcome.decision.decision).toBe('PASS');
    expect(outcome.decision.policy_floor).toBe('PASS');
    expect(outcome.action_status).toBe('ok');
  });
});
