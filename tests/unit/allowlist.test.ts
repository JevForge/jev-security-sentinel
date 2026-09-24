import { describe, expect, it } from 'vitest';
import { annotateFindings, isAllowlistExpired } from '../../src/decision/annotate.js';
import { applyGate } from '../../src/decision/policy.js';
import { DEFAULT_POLICY, resolvePolicy } from '../../src/schemas/sentinel.js';
import type { RawFinding } from '../../src/collectors/common.js';

const row: RawFinding = {
  source: 'sarif',
  category: 'sast',
  severity: 'critical',
  title: 'SQL injection',
  rule_id: 'rule.critical',
  path: 'src/api.ts',
  start_line: 4,
  cve: 'CVE-2024-1111',
  exploitability: 'unknown',
  message: 'query built from input',
  component: '',
  scanner_suppressed: false,
};

describe('allowlist entries', () => {
  it('treats YYYY-MM-DD expiry as end of UTC day', () => {
    expect(isAllowlistExpired('2026-01-01', new Date('2026-01-01T12:00:00Z'))).toBe(false);
    expect(isAllowlistExpired('2026-01-01', new Date('2026-01-02T00:00:01Z'))).toBe(true);
  });

  it('allowlists audited entries and keeps expired findings in scope', () => {
    const policy = resolvePolicy({
      allowlist: {
        rule_ids: [],
        cves: [],
        fingerprints: [],
        paths: [],
        ids: [],
        entries: [
          {
            rule_id: 'rule.critical',
            owner: 'secops@example.com',
            reason: 'Accepted until migration completes',
            expires_at: '2026-12-31',
          },
        ],
      },
    });
    const active = annotateFindings({
      raw: [row],
      policy,
      environment: 'production',
      component: '',
      gateScope: 'all',
      changedPaths: null,
      now: new Date('2026-06-01T00:00:00Z'),
    });
    expect(active[0]?.gate_effect).toBe('allowlisted');
    expect(active[0]?.allowlist_owner).toBe('secops@example.com');
    expect(active[0]?.allowlist_reason).toContain('migration');

    const expired = annotateFindings({
      raw: [row],
      policy,
      environment: 'production',
      component: '',
      gateScope: 'all',
      changedPaths: null,
      now: new Date('2027-01-01T00:00:00Z'),
    });
    expect(expired[0]?.allowlisted).toBe(false);
    expect(expired[0]?.allowlist_expired).toBe(true);
    expect(expired[0]?.gate_effect).toBe('blocking');

    const outcome = applyGate({
      findings: expired,
      policy,
      jev: { status: 'evaluated', decision: 'PASS', confidence: 0.9, explanation: 'ok', abstain: false },
      minConfidence: 0.75,
      lowConfidencePolicy: 'fail',
      sourceErrorPolicy: 'fail',
      reviewMode: 'fail',
      sourceErrors: [],
      truncated: false,
      changedPathsUnknown: false,
    });
    expect(outcome.decision.reason_codes).toContain('ALLOWLIST_EXPIRED');
    expect(outcome.decision.decision).toBe('BLOCK');
  });

  it('flags legacy array allowlists as unaudited', () => {
    const policy = resolvePolicy({
      allowlist: {
        rule_ids: ['rule.critical'],
        cves: [],
        fingerprints: [],
        paths: [],
        ids: [],
        entries: [],
      },
    });
    const findings = annotateFindings({
      raw: [row],
      policy,
      environment: 'production',
      component: '',
      gateScope: 'all',
      changedPaths: null,
    });
    const outcome = applyGate({
      findings,
      policy,
      jev: { status: 'evaluated', decision: 'PASS', confidence: 0.9, explanation: 'ok', abstain: false },
      minConfidence: 0.75,
      lowConfidencePolicy: 'fail',
      sourceErrorPolicy: 'fail',
      reviewMode: 'fail',
      sourceErrors: [],
      truncated: false,
      changedPathsUnknown: false,
    });
    expect(findings[0]?.gate_effect).toBe('allowlisted');
    expect(outcome.decision.reason_codes).toContain('ALLOWLIST_UNAUDITED');
    expect(outcome.decision.reason_codes).toContain('ALLOWLIST_APPLIED');
  });
});
