import {
  DECISION_RANK,
  type GateDecision,
  type LowConfidencePolicy,
  type ReasonCode,
  type ReviewMode,
  type SourceErrorPolicy,
} from '../schemas/enums.js';
import {
  emptySeverityCounts,
  SentinelDecisionSchema,
  type Finding,
  type GatePolicy,
  type SentinelDecision,
  type SourceError,
} from '../schemas/sentinel.js';
import type { JevCallResult } from '../jev/types.js';
import { sanitizeText } from '../utils/sanitize.js';

export type ActionStatus = 'ok' | 'fail' | 'warn' | 'request-review' | 'no-op';

export function stricter(left: GateDecision, right: GateDecision): GateDecision {
  return DECISION_RANK[left] >= DECISION_RANK[right] ? left : right;
}

export function floorDecision(findings: Finding[]): GateDecision {
  return findings.reduce<GateDecision>((floor, finding) => {
    if (finding.gate_effect === 'blocking') return stricter(floor, 'BLOCK');
    if (finding.gate_effect === 'review') return stricter(floor, 'REVIEW');
    if (finding.gate_effect === 'warning') return stricter(floor, 'WARN');
    return floor;
  }, 'PASS');
}

function pushCode(codes: ReasonCode[], code: ReasonCode): void {
  if (!codes.includes(code) && codes.length < 24) codes.push(code);
}

function buildReasons(input: {
  findings: Finding[];
  floor: GateDecision;
  proposed: GateDecision | null;
  finalDecision: GateDecision;
  jev: JevCallResult;
  lowConfidence: boolean;
  changedPathsUnknown: boolean;
  truncated: boolean;
  sourceErrors: SourceError[];
}): ReasonCode[] {
  const codes: ReasonCode[] = [];
  const inScope = input.findings.filter(
    finding =>
      !finding.allowlisted &&
      !finding.excluded &&
      finding.gate_effect !== 'out_of_scope',
  );
  if (input.findings.length === 0) pushCode(codes, 'NO_FINDINGS');
  else pushCode(codes, 'FINDINGS_PRESERVED');
  if (input.findings.length > 0 && inScope.length === 0) pushCode(codes, 'NO_IN_SCOPE_FINDINGS');
  if (inScope.some(finding => finding.severity === 'critical')) pushCode(codes, 'CRITICAL_IN_SCOPE');
  if (inScope.some(finding => finding.severity === 'high')) pushCode(codes, 'HIGH_IN_SCOPE');
  if (inScope.some(finding => finding.severity === 'medium')) pushCode(codes, 'MEDIUM_IN_SCOPE');
  if (inScope.some(finding => finding.exploitability === 'known_exploited')) pushCode(codes, 'KNOWN_EXPLOITED');
  if (inScope.some(finding => finding.exploitability === 'poc')) pushCode(codes, 'POC_AVAILABLE');
  if (inScope.some(finding => finding.category === 'secrets')) {
    pushCode(codes, 'SECRETS_EXPOSED');
    pushCode(codes, 'BLOCK_SECRETS');
  }
  if (inScope.some(finding => finding.category === 'iac')) pushCode(codes, 'IAC_MISCONFIGURATION');
  if (inScope.some(finding => finding.category === 'sca')) pushCode(codes, 'SCA_VULNERABILITY');
  if (inScope.some(finding => finding.category === 'sast')) pushCode(codes, 'SAST_FINDING');
  if (inScope.some(finding => finding.category === 'container')) pushCode(codes, 'CONTAINER_VULNERABILITY');
  if (inScope.some(finding => finding.category === 'license')) pushCode(codes, 'LICENSE_ISSUE');
  if (input.findings.some(finding => finding.environment === 'production')) {
    pushCode(codes, 'PRODUCTION_ENVIRONMENT');
  }
  if (input.findings.some(finding => finding.environment === 'staging')) {
    pushCode(codes, 'STAGING_ENVIRONMENT');
  }
  if (inScope.some(finding => finding.in_change)) pushCode(codes, 'CHANGED_CODE');
  if (input.findings.some(finding => finding.allowlisted)) pushCode(codes, 'ALLOWLIST_APPLIED');
  if (input.findings.some(finding => finding.baseline_matched || finding.gate_effect === 'baseline')) {
    pushCode(codes, 'BASELINE_MATCHED');
    pushCode(codes, 'NEW_FINDINGS_ONLY');
  }
  if (input.floor === 'BLOCK') pushCode(codes, 'POLICY_FLOOR_BLOCK');
  if (input.floor === 'WARN') pushCode(codes, 'POLICY_FLOOR_WARN');
  if (input.floor === 'REVIEW') pushCode(codes, 'POLICY_FLOOR_REVIEW');
  if (input.jev.status === 'unavailable') pushCode(codes, 'JEV_UNAVAILABLE');
  if (input.jev.status === 'schema_rejected') pushCode(codes, 'SCHEMA_REJECTED');
  if (input.jev.status === 'evaluated' && input.jev.abstain) pushCode(codes, 'JEV_ABSTAIN');
  if (input.lowConfidence) pushCode(codes, 'LOW_CONFIDENCE');
  if (
    input.proposed &&
    DECISION_RANK[input.finalDecision] > DECISION_RANK[input.floor] &&
    DECISION_RANK[input.proposed] > DECISION_RANK[input.floor]
  ) {
    pushCode(codes, 'JEV_ESCALATED');
  } else if (input.proposed && input.finalDecision === input.proposed && input.finalDecision === input.floor) {
    pushCode(codes, 'JEV_AGREED');
  }
  if (input.finalDecision === 'REVIEW') pushCode(codes, 'REVIEW_REQUIRED');
  if (input.truncated) pushCode(codes, 'FINDINGS_TRUNCATED');
  if (input.sourceErrors.length) pushCode(codes, 'SOURCE_UNAVAILABLE');
  if (input.changedPathsUnknown) pushCode(codes, 'CHANGED_PATHS_UNKNOWN');
  if (codes.length === 0) pushCode(codes, 'NO_FINDINGS');
  return codes;
}

function summarize(findings: Finding[], errors: SourceError[], truncated: boolean) {
  const bySeverity = emptySeverityCounts();
  const byCategory = { sast: 0, sca: 0, iac: 0, secrets: 0, container: 0, license: 0, other: 0 };
  let blocking = 0;
  let warning = 0;
  let review = 0;
  let allowlisted = 0;
  let outOfScope = 0;
  let baseline = 0;
  let inScope = 0;
  let highest: Finding['severity'] | 'none' = 'none';
  const rank: Record<Finding['severity'], number> = {
    info: 1,
    low: 2,
    unknown: 3,
    medium: 4,
    high: 5,
    critical: 6,
  };
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byCategory[finding.category] += 1;
    if (highest === 'none' || rank[finding.severity] > rank[highest]) highest = finding.severity;
    if (finding.gate_effect === 'blocking') blocking += 1;
    if (finding.gate_effect === 'warning') warning += 1;
    if (finding.gate_effect === 'review') review += 1;
    if (finding.gate_effect === 'allowlisted') allowlisted += 1;
    if (finding.gate_effect === 'out_of_scope') outOfScope += 1;
    if (finding.gate_effect === 'baseline') baseline += 1;
    if (
      finding.gate_effect === 'blocking' ||
      finding.gate_effect === 'warning' ||
      finding.gate_effect === 'review'
    ) {
      inScope += 1;
    }
  }
  return {
    total: findings.length,
    in_scope: inScope,
    blocking,
    warning,
    review,
    allowlisted,
    out_of_scope: outOfScope,
    baseline,
    by_severity: bySeverity,
    by_category: byCategory,
    highest_severity: highest,
    source_errors: errors.slice(0, 32),
    truncated,
  };
}

export interface ApplyGateInput {
  findings: Finding[];
  policy: GatePolicy;
  jev: JevCallResult;
  minConfidence: number;
  lowConfidencePolicy: LowConfidencePolicy;
  sourceErrorPolicy: SourceErrorPolicy;
  reviewMode: ReviewMode;
  sourceErrors: SourceError[];
  truncated: boolean;
  changedPathsUnknown: boolean;
}

export interface GateOutcome {
  decision: SentinelDecision;
  action_status: ActionStatus;
  message: string;
}

export function applyGate(input: ApplyGateInput): GateOutcome {
  const floor = floorDecision(input.findings);
  const lowConfidence =
    input.jev.status === 'evaluated' && input.jev.confidence < input.minConfidence;
  let proposed: GateDecision | null = null;
  let confidence = 0;
  let provisional = input.jev.status !== 'evaluated';
  let explanation = '';

  if (input.jev.status === 'evaluated') {
    proposed = input.jev.abstain ? 'REVIEW' : input.jev.decision;
    confidence = input.jev.confidence;
    explanation = sanitizeText(input.jev.explanation, 2000);
    if (
      proposed === 'BLOCK' &&
      input.findings.length === 0 &&
      input.sourceErrors.length === 0 &&
      !input.truncated
    ) {
      proposed = 'PASS';
    }
  } else {
    confidence = 0;
    explanation = sanitizeText(input.jev.message, 2000);
  }

  let decision = floor;
  if (input.jev.status !== 'evaluated') {
    if (input.lowConfidencePolicy === 'warn') decision = stricter(floor, 'WARN');
    else if (input.lowConfidencePolicy === 'request-review' || input.lowConfidencePolicy === 'fail') {
      decision = stricter(floor, 'REVIEW');
    }
  } else if (lowConfidence) {
    provisional = true;
    if (input.lowConfidencePolicy === 'no-op') decision = floor;
    else if (input.lowConfidencePolicy === 'warn') decision = stricter(floor, proposed ?? floor);
    else decision = stricter(stricter(floor, proposed ?? 'PASS'), 'REVIEW');
  } else {
    decision = stricter(floor, proposed ?? floor);
  }

  if (input.truncated) decision = stricter(decision, 'REVIEW');
  if (input.sourceErrors.length && input.sourceErrorPolicy === 'fail') {
    decision = stricter(decision, 'REVIEW');
  }

  const reasonCodes = buildReasons({
    findings: input.findings,
    floor,
    proposed: input.jev.status === 'evaluated' ? proposed : null,
    finalDecision: decision,
    jev: input.jev,
    lowConfidence,
    changedPathsUnknown: input.changedPathsUnknown,
    truncated: input.truncated,
    sourceErrors: input.sourceErrors,
  });

  const record = SentinelDecisionSchema.parse({
    decision,
    confidence,
    reason_codes: reasonCodes,
    findings: input.findings,
    risk_summary: summarize(input.findings, input.sourceErrors, input.truncated),
    explanation,
    provisional,
    jev_status: input.jev.status,
    jev_proposed: input.jev.status === 'evaluated' ? proposed : null,
    policy_floor: floor,
    policy_id: input.policy.id,
  });

  const jevFailedClosed =
    (input.jev.status !== 'evaluated' || lowConfidence) && input.lowConfidencePolicy === 'fail';
  let actionStatus: ActionStatus = 'ok';
  if (record.decision === 'BLOCK' || jevFailedClosed) actionStatus = 'fail';
  else if (record.decision === 'REVIEW') {
    actionStatus = input.reviewMode === 'fail' ? 'fail' : 'request-review';
  } else if (record.decision === 'WARN' || (input.sourceErrors.length && input.sourceErrorPolicy === 'warn')) {
    actionStatus = 'warn';
  } else if (input.jev.status !== 'evaluated' && input.lowConfidencePolicy === 'no-op') {
    actionStatus = 'no-op';
  }

  const message =
    actionStatus === 'fail'
      ? record.decision === 'BLOCK'
        ? `Security gate blocked (${record.reason_codes.slice(0, 6).join(', ')})`
        : record.explanation || 'Security gate requires attention'
      : record.explanation || record.decision;

  return { decision: record, action_status: actionStatus, message };
}
