export const GATE_DECISIONS = ['PASS', 'WARN', 'BLOCK', 'REVIEW'] as const;
export type GateDecision = (typeof GATE_DECISIONS)[number];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CATEGORIES = [
  'sast',
  'sca',
  'iac',
  'secrets',
  'container',
  'license',
  'other',
] as const;
export type Category = (typeof CATEGORIES)[number];

export const EXPLOITABILITIES = [
  'known_exploited',
  'poc',
  'likely',
  'unlikely',
  'unknown',
] as const;
export type Exploitability = (typeof EXPLOITABILITIES)[number];

export const FINDING_SOURCES = [
  'normalized',
  'sarif',
  'semgrep',
  'trivy',
  'snyk',
  'veracode',
  'github-code-scanning',
  'github-secret-scanning',
  'github-dependabot',
] as const;
export type FindingSource = (typeof FINDING_SOURCES)[number];

export const ENVIRONMENTS = [
  'production',
  'staging',
  'development',
  'test',
  'unknown',
] as const;
export type EnvironmentName = (typeof ENVIRONMENTS)[number];

export const GATE_SCOPES = ['all', 'changed'] as const;
export type GateScope = (typeof GATE_SCOPES)[number];

export const GATE_MODES = ['all', 'new_only'] as const;
export type GateMode = (typeof GATE_MODES)[number];

export const JEV_PROVIDERS = [
  'vercel-ai-gateway',
  'typesafe-native',
  'custom-compatible',
] as const;
export type JevProviderId = (typeof JEV_PROVIDERS)[number];

export const LOW_CONFIDENCE_POLICIES = ['fail', 'warn', 'request-review', 'no-op'] as const;
export type LowConfidencePolicy = (typeof LOW_CONFIDENCE_POLICIES)[number];

export const SOURCE_ERROR_POLICIES = ['fail', 'warn'] as const;
export type SourceErrorPolicy = (typeof SOURCE_ERROR_POLICIES)[number];

export const REVIEW_MODES = ['fail', 'continue'] as const;
export type ReviewMode = (typeof REVIEW_MODES)[number];

export const GATE_EFFECTS = [
  'blocking',
  'warning',
  'review',
  'allowlisted',
  'out_of_scope',
  'baseline',
  'informational',
] as const;
export type GateEffect = (typeof GATE_EFFECTS)[number];

export const JEV_STATUSES = ['evaluated', 'unavailable', 'schema_rejected'] as const;
export type JevStatus = (typeof JEV_STATUSES)[number];

export const REASON_CODES = [
  'CRITICAL_IN_SCOPE',
  'HIGH_IN_SCOPE',
  'MEDIUM_IN_SCOPE',
  'KNOWN_EXPLOITED',
  'POC_AVAILABLE',
  'SECRETS_EXPOSED',
  'IAC_MISCONFIGURATION',
  'SCA_VULNERABILITY',
  'SAST_FINDING',
  'CONTAINER_VULNERABILITY',
  'LICENSE_ISSUE',
  'PRODUCTION_ENVIRONMENT',
  'STAGING_ENVIRONMENT',
  'CHANGED_CODE',
  'ALLOWLIST_APPLIED',
  'ALLOWLIST_EXPIRED',
  'ALLOWLIST_UNAUDITED',
  'POLICY_FLOOR_BLOCK',
  'POLICY_FLOOR_WARN',
  'POLICY_FLOOR_REVIEW',
  'JEV_ESCALATED',
  'JEV_AGREED',
  'JEV_ABSTAIN',
  'LOW_CONFIDENCE',
  'JEV_UNAVAILABLE',
  'SCHEMA_REJECTED',
  'NO_FINDINGS',
  'NO_IN_SCOPE_FINDINGS',
  'FINDINGS_PRESERVED',
  'FINDINGS_TRUNCATED',
  'REVIEW_REQUIRED',
  'SOURCE_UNAVAILABLE',
  'CHANGED_PATHS_UNKNOWN',
  'BLOCK_SECRETS',
  'BASELINE_MATCHED',
  'NEW_FINDINGS_ONLY',
  'KEV_MATCHED',
  'EPSS_ENRICHED',
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

export const DECISION_RANK: Record<GateDecision, number> = {
  PASS: 0,
  WARN: 1,
  REVIEW: 2,
  BLOCK: 3,
};

export const EFFECT_RANK: Record<GateEffect, number> = {
  informational: 0,
  out_of_scope: 0,
  allowlisted: 0,
  baseline: 0,
  warning: 1,
  review: 2,
  blocking: 3,
};
