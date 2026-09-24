import { describe, expect, it } from 'vitest';
import { annotateFindings, dependencyManifestChanged } from '../../src/decision/annotate.js';
import { DEFAULT_POLICY } from '../../src/schemas/sentinel.js';
import type { RawFinding } from '../../src/collectors/common.js';

describe('SCA lockfile change scope', () => {
  it('detects dependency manifests in the change set', () => {
    expect(dependencyManifestChanged(['src/a.ts', 'package-lock.json'])).toBe(true);
    expect(dependencyManifestChanged(['src/a.ts'])).toBe(false);
  });

  it('marks SCA findings in-change when package-lock.json changes', () => {
    const row: RawFinding = {
      source: 'trivy',
      category: 'sca',
      severity: 'high',
      title: 'lodash',
      rule_id: 'CVE-2021-23337',
      path: 'node_modules/lodash/package.json',
      start_line: null,
      cve: 'CVE-2021-23337',
      exploitability: 'poc',
      message: '',
      component: 'lodash',
      scanner_suppressed: false,
    };
    const findings = annotateFindings({
      raw: [row],
      policy: DEFAULT_POLICY,
      environment: 'production',
      component: '',
      gateScope: 'changed',
      changedPaths: ['package-lock.json'],
    });
    expect(findings[0]?.in_change).toBe(true);
    expect(findings[0]?.gate_effect).not.toBe('out_of_scope');
  });
});
