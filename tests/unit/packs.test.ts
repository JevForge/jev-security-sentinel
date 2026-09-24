import { describe, expect, it } from 'vitest';
import { resolvePolicyPack } from '../../src/decision/packs.js';
import { annotateFindings } from '../../src/decision/annotate.js';
import type { RawFinding } from '../../src/collectors/common.js';

const medium: RawFinding = {
  source: 'sarif',
  category: 'sast',
  severity: 'medium',
  title: 'xss',
  rule_id: 'xss',
  path: 'src/a.ts',
  start_line: 1,
  cve: null,
  exploitability: 'unknown',
  message: '',
  component: '',
  scanner_suppressed: false,
};

describe('policy packs', () => {
  it('strict-prod blocks medium findings in production', () => {
    const policy = resolvePolicyPack('strict-prod');
    expect(policy.id).toBe('pack:strict-prod');
    const findings = annotateFindings({
      raw: [medium],
      policy,
      environment: 'production',
      component: '',
      gateScope: 'all',
      changedPaths: null,
    });
    expect(findings[0]?.gate_effect).toBe('blocking');
  });

  it('startup only warns on medium in production', () => {
    const policy = resolvePolicyPack('startup');
    const findings = annotateFindings({
      raw: [medium],
      policy,
      environment: 'production',
      component: '',
      gateScope: 'all',
      changedPaths: null,
    });
    expect(findings[0]?.gate_effect).toBe('warning');
  });

  it('compliance reviews medium in production', () => {
    const policy = resolvePolicyPack('compliance');
    const findings = annotateFindings({
      raw: [medium],
      policy,
      environment: 'production',
      component: '',
      gateScope: 'all',
      changedPaths: null,
    });
    expect(findings[0]?.gate_effect).toBe('review');
  });
});
