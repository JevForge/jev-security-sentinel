import type { SentinelDecision } from '../schemas/sentinel.js';

export function buildCommentMarkdown(decision: SentinelDecision): string {
  const lines = [
    '### JEV Security Sentinel',
    '',
    `- **Decision:** \`${decision.decision}\``,
    `- **Policy floor:** \`${decision.policy_floor}\``,
    `- **Jev proposed:** \`${decision.jev_proposed ?? 'none'}\``,
    `- **Jev status:** \`${decision.jev_status}\``,
    `- **Confidence:** ${decision.confidence.toFixed(3)}`,
    `- **Provisional:** ${decision.provisional ? 'yes' : 'no'}`,
    `- **Reason codes:** ${decision.reason_codes.map(code => `\`${code}\``).join(', ')}`,
    `- **Findings:** ${decision.risk_summary.total} visible, ${decision.risk_summary.blocking} blocking, ${decision.risk_summary.allowlisted} allowlisted`,
    '',
    '| Severity | Category | Rule | Path | Gate |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const finding of decision.findings.slice(0, 15)) {
    const path = finding.path ? `${finding.path}${finding.start_line ? `:${finding.start_line}` : ''}` : 'n/a';
    lines.push(
      `| ${finding.severity} | ${finding.category} | ${finding.rule_id.replaceAll('|', '/')} | ${path.replaceAll('|', '/')} | ${finding.gate_effect} |`,
    );
  }
  if (decision.findings.length > 15) {
    lines.push('', `_ ${decision.findings.length - 15} more findings are preserved in the Action outputs._`);
  }
  lines.push('', '_Every collected finding stays visible. Allowlisting changes the gate effect only._');
  return lines.join('\n');
}

export interface CommentClient {
  createComment(body: string): Promise<void>;
}

export async function maybePostComment(
  enabled: boolean,
  dryRun: boolean,
  decision: SentinelDecision,
  client: CommentClient | null,
): Promise<'posted' | 'dry-run' | 'skipped'> {
  if (!enabled) return 'skipped';
  if (dryRun || !client) return 'dry-run';
  await client.createComment(buildCommentMarkdown(decision));
  return 'posted';
}
