import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSarif, writeArtifactReports } from '../../src/executors/artifacts.js';
import type { SentinelDecision } from '../../src/schemas/sentinel.js';

const decision: SentinelDecision = {
  decision: 'BLOCK',
  confidence: 0.9,
  reason_codes: ['CRITICAL_IN_SCOPE'],
  findings: [
    {
      id: '1',
      fingerprint: 'abcd1234abcd1234',
      source: 'sarif',
      category: 'sast',
      severity: 'critical',
      title: 'sqli',
      rule_id: 'sql-injection',
      path: 'src/db.ts',
      start_line: 12,
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
    },
  ],
  risk_summary: {
    total: 1,
    in_scope: 1,
    blocking: 1,
    warning: 0,
    review: 0,
    allowlisted: 0,
    out_of_scope: 0,
    baseline: 0,
    by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    by_category: { sast: 1, sca: 0, iac: 0, secrets: 0, container: 0, license: 0, other: 0 },
    highest_severity: 'critical',
    source_errors: [],
    truncated: false,
  },
  explanation: '',
  provisional: false,
  jev_status: 'evaluated',
  jev_proposed: 'BLOCK',
  policy_floor: 'BLOCK',
  policy_id: 'default-gate',
};

describe('artifact reports', () => {
  it('writes SARIF and markdown/json reports', () => {
    const root = mkdtempSync(join(tmpdir(), 'sentinel-art-'));
    const sarif = buildSarif(decision) as { runs: Array<{ results: unknown[] }> };
    expect(sarif.runs[0]?.results).toHaveLength(1);
    const paths = writeArtifactReports({
      workspace: root,
      decision,
      writeSarif: true,
      writeMarkdown: true,
      writeJson: true,
    });
    expect(readFileSync(paths.sarifPath!, 'utf8')).toContain('sql-injection');
    expect(readFileSync(paths.markdownPath!, 'utf8')).toContain('JEV Security Sentinel report');
    expect(readFileSync(paths.jsonPath!, 'utf8')).toContain('"decision": "BLOCK"');
  });
});
