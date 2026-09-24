import type { Finding } from '../schemas/sentinel.js';
import type { ActionStatus } from '../decision/policy.js';
import type { SentinelDecision } from '../schemas/sentinel.js';

export const ALLOWED_EFFECTS = [
  'set-outputs',
  'fail-step',
  'warn-step',
  'request-review',
  'no-op',
  'pull-request-comment',
  'file-annotation',
  'check-run',
] as const;

export type AllowedEffect = (typeof ALLOWED_EFFECTS)[number];

export interface AnnotationRequest {
  path: string;
  startLine: number;
  level: 'error' | 'warning' | 'notice';
  title: string;
  message: string;
}

export interface PlannedEffects {
  effects: AllowedEffect[];
  annotations: AnnotationRequest[];
  fail: boolean;
}

function annotationLevel(finding: Finding): AnnotationRequest['level'] | null {
  if (finding.gate_effect === 'blocking') return 'error';
  if (finding.gate_effect === 'review') return 'warning';
  if (finding.gate_effect === 'warning') return 'notice';
  return null;
}

export function planEffects(input: {
  decision: SentinelDecision;
  actionStatus: ActionStatus;
  annotate: boolean;
  comment: boolean;
  checkRun: boolean;
}): PlannedEffects {
  const effects: AllowedEffect[] = ['set-outputs'];
  if (input.actionStatus === 'fail') effects.push('fail-step');
  else if (input.actionStatus === 'warn') effects.push('warn-step');
  else if (input.actionStatus === 'request-review') effects.push('request-review');
  else if (input.actionStatus === 'no-op') effects.push('no-op');
  if (input.comment) effects.push('pull-request-comment');
  if (input.checkRun) effects.push('check-run');

  const annotations: AnnotationRequest[] = [];
  if (input.annotate) {
    effects.push('file-annotation');
    for (const finding of input.decision.findings) {
      const level = annotationLevel(finding);
      if (!level || !finding.path || !finding.start_line) continue;
      if (finding.path.includes('..')) continue;
      annotations.push({
        path: finding.path,
        startLine: finding.start_line,
        level,
        title: finding.rule_id,
        message: `${finding.severity} ${finding.category}: ${finding.title}`.slice(0, 400),
      });
      if (annotations.length >= 30) break;
    }
  }

  return {
    effects,
    annotations,
    fail: input.actionStatus === 'fail',
  };
}
