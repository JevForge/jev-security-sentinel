import { describe, expect, it } from 'vitest';
import {
  buildCheckSummary,
  checkConclusion,
  maybeCreateCheckRun,
} from '../../src/executors/check-run.js';
import { COMMENT_MARKER, maybePostComment } from '../../src/executors/comment.js';
import type { SentinelDecision } from '../../src/schemas/sentinel.js';

const decision: SentinelDecision = {
  decision: 'BLOCK',
  confidence: 0.9,
  reason_codes: ['CRITICAL_IN_SCOPE', 'POLICY_FLOOR_BLOCK'],
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

describe('check run and idempotent comment', () => {
  it('maps action status to check conclusions', () => {
    expect(checkConclusion('ok')).toBe('success');
    expect(checkConclusion('fail')).toBe('failure');
    expect(checkConclusion('warn')).toBe('neutral');
  });

  it('creates a check run when enabled', async () => {
    const calls: unknown[] = [];
    const status = await maybeCreateCheckRun(
      true,
      false,
      'abc123',
      decision,
      'fail',
      {
        async createCheckRun(input) {
          calls.push(input);
        },
      },
    );
    expect(status).toBe('created');
    expect(calls[0]).toMatchObject({
      name: 'JEV Security Sentinel',
      headSha: 'abc123',
      conclusion: 'failure',
    });
    expect(buildCheckSummary(decision)).toContain('sql-injection');
  });

  it('updates an existing marked PR comment instead of creating another', async () => {
    const created: string[] = [];
    const updated: Array<{ id: number; body: string }> = [];
    const status = await maybePostComment(true, false, decision, {
      async listComments() {
        return [{ id: 42, body: `${COMMENT_MARKER}\nold` }];
      },
      async createComment(body) {
        created.push(body);
      },
      async updateComment(id, body) {
        updated.push({ id, body });
      },
    });
    expect(status).toBe('updated');
    expect(created).toEqual([]);
    expect(updated[0]?.id).toBe(42);
    expect(updated[0]?.body).toContain(COMMENT_MARKER);
    expect(updated[0]?.body).toContain('BLOCK');
  });
});
