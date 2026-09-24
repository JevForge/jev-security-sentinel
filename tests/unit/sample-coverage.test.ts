import { describe, expect, it } from 'vitest';
import { sampleForJev } from '../../src/decision/prioritize.js';
import type { Finding } from '../../src/schemas/sentinel.js';

function finding(partial: Partial<Finding> & Pick<Finding, 'id' | 'category' | 'severity'>): Finding {
  return {
    fingerprint: 'abcd1234abcd1234',
    source: 'sarif',
    title: partial.category,
    rule_id: partial.id,
    path: 'src/a.ts',
    start_line: 1,
    component: '',
    environment: 'production',
    cve: null,
    exploitability: 'unknown',
    in_change: true,
    allowlisted: false,
    allowlist_owner: null,
    allowlist_reason: null,
    allowlist_expires_at: null,
    allowlist_expired: false,
    epss: null,
    kev: false,
    excluded: false,
    baseline_matched: false,
    gate_effect: 'blocking',
    message: '',
    ...partial,
  };
}

describe('sampleForJev category coverage', () => {
  it('includes at least one finding per category when limit allows', () => {
    const findings = [
      finding({ id: 'sast-1', category: 'sast', severity: 'critical' }),
      finding({ id: 'sast-2', category: 'sast', severity: 'high' }),
      finding({ id: 'sca-1', category: 'sca', severity: 'medium' }),
      finding({ id: 'iac-1', category: 'iac', severity: 'low' }),
    ];
    const sample = sampleForJev(findings, 3);
    const categories = new Set(sample.map(item => item.category));
    expect(categories.has('sast')).toBe(true);
    expect(categories.has('sca')).toBe(true);
    expect(categories.has('iac')).toBe(true);
    expect(sample).toHaveLength(3);
  });
});
