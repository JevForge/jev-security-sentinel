import type { ActionStatus } from '../decision/policy.js';
import type { SentinelDecision } from '../schemas/sentinel.js';

export function checkConclusion(
  actionStatus: ActionStatus,
): 'success' | 'neutral' | 'failure' {
  if (actionStatus === 'ok') return 'success';
  if (actionStatus === 'fail') return 'failure';
  return 'neutral';
}

export function buildCheckSummary(decision: SentinelDecision): string {
  const top = decision.findings.slice(0, 10);
  const rows = top.map(finding => {
    const path = finding.path
      ? `${finding.path}${finding.start_line ? `:${finding.start_line}` : ''}`
      : 'n/a';
    return `| ${finding.severity} | ${finding.category} | ${finding.rule_id.replaceAll('|', '/')} | ${path.replaceAll('|', '/')} | ${finding.gate_effect} |`;
  });
  return [
    '### JEV Security Sentinel',
    '',
    '| Field | Value |',
    '| --- | --- |',
    `| Decision | \`${decision.decision}\` |`,
    `| Policy floor | \`${decision.policy_floor}\` |`,
    `| Jev proposed | \`${decision.jev_proposed ?? 'none'}\` |`,
    `| Jev status | \`${decision.jev_status}\` |`,
    `| Confidence | ${decision.confidence.toFixed(3)} |`,
    `| Provisional | ${decision.provisional ? 'yes' : 'no'} |`,
    `| Findings | ${decision.risk_summary.total} visible / ${decision.risk_summary.blocking} blocking |`,
    `| Reason codes | ${decision.reason_codes.map(code => `\`${code}\``).join(', ') || '`none`'} |`,
    '',
    '| Severity | Category | Rule | Path | Gate |',
    '| --- | --- | --- | --- | --- |',
    ...(rows.length > 0 ? rows : ['| — | — | — | — | — |']),
    '',
    '_Every collected finding stays visible. Allowlisting changes the gate effect only._',
  ].join('\n');
}

export interface CheckRunClient {
  createCheckRun(input: {
    name: string;
    headSha: string;
    conclusion: 'success' | 'neutral' | 'failure';
    title: string;
    summary: string;
  }): Promise<void>;
}

export async function maybeCreateCheckRun(
  enabled: boolean,
  dryRun: boolean,
  headSha: string | null,
  decision: SentinelDecision,
  actionStatus: ActionStatus,
  client: CheckRunClient | null,
): Promise<'created' | 'dry-run' | 'skipped'> {
  if (!enabled) return 'skipped';
  if (!headSha) return 'skipped';
  if (dryRun || !client) return 'dry-run';

  await client.createCheckRun({
    name: 'JEV Security Sentinel',
    headSha,
    conclusion: checkConclusion(actionStatus),
    title: `${decision.decision} · floor ${decision.policy_floor}`,
    summary: buildCheckSummary(decision),
  });
  return 'created';
}
