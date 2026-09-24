import { describe, expect, it } from 'vitest';
import { annotateFindings } from '../../src/decision/annotate.js';
import { applyGate } from '../../src/decision/policy.js';
import { DEFAULT_POLICY, resolvePolicy } from '../../src/schemas/sentinel.js';
import type { RawFinding } from '../../src/collectors/common.js';

function raw(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
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
    ...overrides,
  };
}

function run(options: {
  rows?: RawFinding[];
  jev?: 'PASS' | 'WARN' | 'BLOCK' | 'REVIEW';
  confidence?: number;
  policy?: ReturnType<typeof resolvePolicy>;
  jevStatus?: 'evaluated' | 'unavailable' | 'schema_rejected';
  low?: 'fail' | 'warn' | 'request-review' | 'no-op';
  scope?: 'all' | 'changed';
  changed?: string[] | null;
  unknownPaths?: boolean;
  errors?: { source: string; message: string }[];
  truncated?: boolean;
  min?: number;
  environment?: 'production' | 'development';
}) {
  const policy = options.policy ?? DEFAULT_POLICY;
  const findings = annotateFindings({
    raw: options.rows ?? [raw()],
    policy,
    environment: options.environment ?? 'production',
    component: 'billing',
    gateScope: options.scope ?? 'all',
    changedPaths: options.unknownPaths ? null : (options.changed ?? null),
  });
  const status = options.jevStatus ?? 'evaluated';
  return applyGate({
    findings,
    policy,
    jev:
      status === 'evaluated'
        ? {
            status,
            decision: options.jev ?? 'PASS',
            confidence: options.confidence ?? 0.92,
            explanation: 'sample',
            abstain: false,
          }
        : { status, message: 'Jev did not return a decision' },
    minConfidence: options.min ?? 0.75,
    lowConfidencePolicy: options.low ?? 'fail',
    sourceErrorPolicy: 'fail',
    reviewMode: 'fail',
    sourceErrors: options.errors ?? [],
    truncated: options.truncated ?? false,
    changedPathsUnknown: options.unknownPaths ?? false,
  });
}

describe('deterministic gate', () => {
  it('raises a Jev PASS to BLOCK when production policy sees a critical finding', () => {
    const outcome = run({ jev: 'PASS' });
    expect(outcome.decision.decision).toBe('BLOCK');
    expect(outcome.decision.policy_floor).toBe('BLOCK');
    expect(outcome.decision.jev_proposed).toBe('PASS');
    expect(outcome.decision.findings[0]?.gate_effect).toBe('blocking');
    expect(outcome.decision.reason_codes).toContain('POLICY_FLOOR_BLOCK');
    expect(outcome.action_status).toBe('fail');
  });

  it('lets Jev escalate a low finding to BLOCK', () => {
    const outcome = run({
      rows: [raw({ severity: 'low', category: 'other', cve: null })],
      jev: 'BLOCK',
    });
    expect(outcome.decision.policy_floor).toBe('PASS');
    expect(outcome.decision.decision).toBe('BLOCK');
    expect(outcome.decision.reason_codes).toContain('JEV_ESCALATED');
    expect(outcome.decision.findings).toHaveLength(1);
  });

  it('keeps allowlisted findings visible without letting them block', () => {
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
    const outcome = run({ policy, jev: 'PASS' });
    expect(outcome.decision.findings[0]?.allowlisted).toBe(true);
    expect(outcome.decision.findings[0]?.gate_effect).toBe('allowlisted');
    expect(outcome.decision.decision).toBe('PASS');
    expect(outcome.decision.reason_codes).toContain('ALLOWLIST_APPLIED');
    expect(outcome.decision.reason_codes).toContain('FINDINGS_PRESERVED');
  });

  it('blocks exposed secrets even when severity is low', () => {
    const outcome = run({
      rows: [raw({ category: 'secrets', severity: 'low', title: 'aws key', cve: null, message: '' })],
      jev: 'PASS',
    });
    expect(outcome.decision.decision).toBe('BLOCK');
    expect(outcome.decision.reason_codes).toContain('SECRETS_EXPOSED');
    expect(outcome.decision.findings[0]?.message).toBe('');
  });

  it('does not pretend Jev decided when the provider is unavailable', () => {
    const outcome = run({ jevStatus: 'unavailable', low: 'fail', rows: [] });
    expect(outcome.decision.jev_status).toBe('unavailable');
    expect(outcome.decision.jev_proposed).toBeNull();
    expect(outcome.decision.provisional).toBe(true);
    expect(outcome.decision.decision).not.toBe('PASS');
    expect(outcome.decision.reason_codes).toContain('JEV_UNAVAILABLE');
    expect(outcome.action_status).toBe('fail');
  });

  it('uses only the deterministic floor when Jev is unavailable and the policy is no-op', () => {
    const outcome = run({
      jevStatus: 'unavailable',
      low: 'no-op',
      rows: [raw({ severity: 'info', category: 'license', cve: null })],
    });
    expect(outcome.decision.decision).toBe('PASS');
    expect(outcome.decision.provisional).toBe(true);
    expect(outcome.decision.reason_codes).toContain('JEV_UNAVAILABLE');
    expect(outcome.action_status).toBe('no-op');
  });

  it('fails closed on low confidence instead of accepting a pass', () => {
    const outcome = run({
      rows: [raw({ severity: 'low', category: 'other', cve: null })],
      jev: 'PASS',
      confidence: 0.2,
      low: 'fail',
    });
    expect(outcome.decision.provisional).toBe(true);
    expect(outcome.decision.decision).toBe('REVIEW');
    expect(outcome.decision.reason_codes).toContain('LOW_CONFIDENCE');
    expect(outcome.action_status).toBe('fail');
  });

  it('keeps changed-scope findings out of the floor and still reports them', () => {
    const outcome = run({
      scope: 'changed',
      changed: ['docs/readme.md'],
      jev: 'PASS',
    });
    expect(outcome.decision.findings[0]?.in_change).toBe(false);
    expect(outcome.decision.findings[0]?.gate_effect).toBe('out_of_scope');
    expect(outcome.decision.decision).toBe('PASS');
    expect(outcome.decision.findings).toHaveLength(1);
  });

  it('raises review when a source is truncated or unavailable', () => {
    const truncated = run({
      rows: [raw({ severity: 'info', category: 'other', cve: null })],
      truncated: true,
      jev: 'PASS',
    });
    expect(truncated.decision.decision).toBe('REVIEW');
    expect(truncated.decision.reason_codes).toContain('FINDINGS_TRUNCATED');

    const missing = run({
      rows: [],
      jev: 'PASS',
      errors: [{ source: 'snyk', message: 'HTTP 401' }],
    });
    expect(missing.decision.reason_codes).toContain('SOURCE_UNAVAILABLE');
    expect(missing.decision.decision).toBe('REVIEW');
  });

  it('rejects a schema-invalid Jev payload without using it as a pass', () => {
    const outcome = run({ jevStatus: 'schema_rejected', low: 'request-review' });
    expect(outcome.decision.jev_proposed).toBeNull();
    expect(outcome.decision.reason_codes).toContain('SCHEMA_REJECTED');
    expect(outcome.decision.decision).toBe('BLOCK');
  });
});
