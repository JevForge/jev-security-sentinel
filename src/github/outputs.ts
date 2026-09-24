import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { SentinelDecision } from '../schemas/sentinel.js';
import type { ActionStatus } from '../decision/policy.js';

export interface ActionOutputWriter {
  setOutput(name: string, value: string): void;
  setFailed(message: string): void;
  warning(message: string, properties?: { file?: string; startLine?: number; title?: string }): void;
  info(message: string): void;
  error(message: string, properties?: { file?: string; startLine?: number; title?: string }): void;
  notice(message: string, properties?: { file?: string; startLine?: number; title?: string }): void;
}

const OUTPUT_LIMIT = 60_000;

export function writeDecisionOutputs(
  writer: ActionOutputWriter,
  decision: SentinelDecision,
  actionStatus: ActionStatus,
  workspace?: string,
): { spilled: boolean } {
  const findingsJson = JSON.stringify(decision.findings);
  const spilled = findingsJson.length > OUTPUT_LIMIT;
  writer.setOutput('decision', decision.decision);
  writer.setOutput('confidence', String(decision.confidence));
  writer.setOutput('reason_codes', JSON.stringify(decision.reason_codes));
  writer.setOutput('risk_summary', JSON.stringify(decision.risk_summary));
  writer.setOutput('provisional', String(decision.provisional));
  writer.setOutput('jev_status', decision.jev_status);
  writer.setOutput('jev_proposed', decision.jev_proposed ?? '');
  writer.setOutput('policy_floor', decision.policy_floor);
  writer.setOutput('policy_id', decision.policy_id);
  writer.setOutput('blocking_count', String(decision.risk_summary.blocking));
  writer.setOutput('findings_count', String(decision.findings.length));
  writer.setOutput(
    'summary',
    `${decision.decision} floor=${decision.policy_floor} jev=${decision.jev_proposed ?? decision.jev_status} findings=${decision.findings.length}`,
  );
  if (spilled && workspace) {
    const dir = join(workspace, '.jev');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, 'security-sentinel-findings.json');
    writeFileSync(file, findingsJson);
    writer.setOutput('findings', '');
    writer.setOutput('findings_file', file);
  } else {
    writer.setOutput('findings', findingsJson);
    writer.setOutput('findings_file', '');
  }
  writer.setOutput('findings_spilled', String(spilled));

  if (actionStatus === 'fail') writer.setFailed(`${decision.decision}: ${decision.explanation || decision.reason_codes.join(',')}`);
  else if (actionStatus === 'warn') writer.warning(decision.explanation || 'Security gate warning');
  else if (actionStatus === 'request-review') writer.warning('Security gate requires human review');
  else writer.info(decision.explanation || decision.decision);

  return { spilled };
}
