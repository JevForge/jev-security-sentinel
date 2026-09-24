import { describe, expect, it, vi } from 'vitest';
import { runSentinel } from '../../src/run.js';
import { DEFAULT_POLICY } from '../../src/schemas/sentinel.js';
import type { JevProvider } from '../../src/jev/types.js';
import type { RawFinding } from '../../src/collectors/common.js';
import { writeDecisionOutputs } from '../../src/github/outputs.js';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const rows: RawFinding[] = [
  {
    source: 'semgrep',
    category: 'sast',
    severity: 'high',
    title: 'eval',
    rule_id: 'javascript.eval',
    path: 'src/app.js',
    start_line: 4,
    cve: null,
    exploitability: 'unknown',
    message: 'eval detected',
    component: '',
    scanner_suppressed: false,
  },
  {
    source: 'trivy',
    category: 'sca',
    severity: 'medium',
    title: 'lodash',
    rule_id: 'CVE-2021-23337',
    path: 'package.json',
    start_line: null,
    cve: 'CVE-2021-23337',
    exploitability: 'poc',
    message: 'command injection',
    component: 'lodash',
    scanner_suppressed: false,
  },
];

describe('runSentinel', () => {
  it('preserves every finding and ignores a weaker Jev pass', async () => {
    const provider: JevProvider = {
      id: 'custom-compatible',
      async evaluateGate(state) {
        expect(state.sample.length).toBeGreaterThan(0);
        expect(state.policyFloor).toBe('BLOCK');
        expect(JSON.stringify(state)).not.toContain('AKIA');
        return {
          status: 'evaluated',
          decision: 'PASS',
          confidence: 0.93,
          explanation: 'looks fine',
          abstain: false,
        };
      },
    };
    const comments: string[] = [];
    const result = await runSentinel({
      rawFindings: rows,
      sourceErrors: [],
      truncated: false,
      policy: DEFAULT_POLICY,
      changedPaths: ['src/app.js', 'package.json'],
      provider,
      commentClient: { async createComment(body) { comments.push(body); } },
      options: {
        environment: 'production',
        gate_scope: 'changed',
        comment_on_github: true,
        dry_run: false,
        min_confidence: 0.75,
        low_confidence_policy: 'fail',
      },
    });
    expect(result.findings).toHaveLength(2);
    expect(result.decision.decision).toBe('BLOCK');
    expect(result.decision.jev_proposed).toBe('PASS');
    expect(result.commentStatus).toBe('posted');
    expect(comments[0]).toContain('JEV Security Sentinel');
    expect(result.effects.fail).toBe(true);
    expect(result.effects.effects).toContain('pull-request-comment');
    expect(result.effects.effects).not.toContain('delete-repository');
  });

  it('spills large finding output to a workspace file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sentinel-out-'));
    const failed: string[] = [];
    const outputs = new Map<string, string>();
    const decision = {
      decision: 'PASS' as const,
      confidence: 1,
      reason_codes: ['NO_FINDINGS' as const],
      findings: [],
      risk_summary: {
        total: 0,
        in_scope: 0,
        blocking: 0,
        warning: 0,
        review: 0,
        allowlisted: 0,
        out_of_scope: 0,
        baseline: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
        by_category: { sast: 0, sca: 0, iac: 0, secrets: 0, container: 0, license: 0, other: 0 },
        highest_severity: 'none' as const,
        source_errors: [],
        truncated: false,
      },
      explanation: '',
      provisional: false,
      jev_status: 'evaluated' as const,
      jev_proposed: 'PASS' as const,
      policy_floor: 'PASS' as const,
      policy_id: 'default-gate',
    };
    const huge = { ...decision, findings: Array.from({ length: 1 }, () => ({ pad: 'x'.repeat(70_000) })) };
    writeDecisionOutputs(
      {
        setOutput: (name, value) => outputs.set(name, value),
        setFailed: message => failed.push(message),
        warning: vi.fn(),
        info: vi.fn(),
        error: vi.fn(),
        notice: vi.fn(),
      },
      huge as unknown as typeof decision,
      'ok',
      dir,
    );
    expect(outputs.get('findings_spilled')).toBe('true');
    expect(outputs.get('findings')).toBe('');
    expect(failed).toEqual([]);
  });
});
