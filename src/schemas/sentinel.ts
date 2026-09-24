import { z } from 'zod';
import {
  CATEGORIES,
  DECISION_RANK,
  EFFECT_RANK,
  ENVIRONMENTS,
  EXPLOITABILITIES,
  FINDING_SOURCES,
  GATE_DECISIONS,
  GATE_EFFECTS,
  GATE_SCOPES,
  GATE_MODES,
  JEV_PROVIDERS,
  JEV_STATUSES,
  LOW_CONFIDENCE_POLICIES,
  REASON_CODES,
  REVIEW_MODES,
  SEVERITIES,
  SOURCE_ERROR_POLICIES,
  type EnvironmentName,
  type Severity,
} from './enums.js';

export const FindingSchema = z
  .object({
    id: z.string().min(1).max(256),
    fingerprint: z.string().min(8).max(64),
    source: z.enum(FINDING_SOURCES),
    category: z.enum(CATEGORIES),
    severity: z.enum(SEVERITIES),
    title: z.string().min(1).max(300),
    rule_id: z.string().min(1).max(256),
    path: z.string().max(512).nullable(),
    start_line: z.number().int().positive().nullable(),
    component: z.string().max(128),
    environment: z.enum(ENVIRONMENTS),
    cve: z.string().max(64).nullable(),
    exploitability: z.enum(EXPLOITABILITIES),
    in_change: z.boolean(),
    allowlisted: z.boolean(),
    allowlist_owner: z.string().max(128).nullable().default(null),
    allowlist_reason: z.string().max(500).nullable().default(null),
    allowlist_expires_at: z.string().max(32).nullable().default(null),
    allowlist_expired: z.boolean().default(false),
    epss: z.number().min(0).max(1).nullable().default(null),
    kev: z.boolean().default(false),
    excluded: z.boolean(),
    baseline_matched: z.boolean().default(false),
    gate_effect: z.enum(GATE_EFFECTS),
    message: z.string().max(500),
  })
  .strict();

export type Finding = z.infer<typeof FindingSchema>;

export const SourceErrorSchema = z
  .object({
    source: z.string().min(1).max(64),
    message: z.string().min(1).max(300),
  })
  .strict();

export type SourceError = z.infer<typeof SourceErrorSchema>;

const severityCounts = z.object({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  info: z.number().int().nonnegative(),
  unknown: z.number().int().nonnegative(),
});

const categoryCounts = z.object({
  sast: z.number().int().nonnegative(),
  sca: z.number().int().nonnegative(),
  iac: z.number().int().nonnegative(),
  secrets: z.number().int().nonnegative(),
  container: z.number().int().nonnegative(),
  license: z.number().int().nonnegative(),
  other: z.number().int().nonnegative(),
});

export const RiskSummarySchema = z
  .object({
    total: z.number().int().nonnegative(),
    in_scope: z.number().int().nonnegative(),
    blocking: z.number().int().nonnegative(),
    warning: z.number().int().nonnegative(),
    review: z.number().int().nonnegative(),
    allowlisted: z.number().int().nonnegative(),
    out_of_scope: z.number().int().nonnegative(),
    baseline: z.number().int().nonnegative(),
    by_severity: severityCounts,
    by_category: categoryCounts,
    highest_severity: z.enum([...SEVERITIES, 'none'] as const),
    source_errors: z.array(SourceErrorSchema).max(32),
    truncated: z.boolean(),
  })
  .strict();

export type RiskSummary = z.infer<typeof RiskSummarySchema>;

export const SentinelDecisionSchema = z
  .object({
    decision: z.enum(GATE_DECISIONS),
    confidence: z.number().min(0).max(1),
    reason_codes: z.array(z.enum(REASON_CODES)).min(1).max(24),
    findings: z.array(FindingSchema).max(5000),
    risk_summary: RiskSummarySchema,
    explanation: z.string().max(2000),
    provisional: z.boolean(),
    jev_status: z.enum(JEV_STATUSES),
    jev_proposed: z.enum(GATE_DECISIONS).nullable(),
    policy_floor: z.enum(GATE_DECISIONS),
    policy_id: z.string().min(1).max(128),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.risk_summary.total !== value.findings.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'risk_summary.total must equal findings.length',
        path: ['risk_summary', 'total'],
      });
    }
    const required = value.findings.reduce(
      (rank, finding) => Math.max(rank, EFFECT_RANK[finding.gate_effect]),
      0,
    );
    if (DECISION_RANK[value.decision] < required) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'decision is weaker than a visible finding gate_effect',
        path: ['decision'],
      });
    }
    if (
      value.decision === 'BLOCK' &&
      value.findings.length === 0 &&
      value.risk_summary.source_errors.length === 0 &&
      !value.risk_summary.truncated
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'BLOCK requires preserved findings or a source failure',
        path: ['decision'],
      });
    }
    if (value.findings.length > 0 && !value.reason_codes.includes('FINDINGS_PRESERVED')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'findings require FINDINGS_PRESERVED',
        path: ['reason_codes'],
      });
    }
    if (value.jev_status === 'evaluated' && !value.jev_proposed) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'evaluated Jev responses require jev_proposed',
        path: ['jev_proposed'],
      });
    }
    if (value.jev_status !== 'evaluated' && value.jev_proposed) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'unavailable Jev must not invent jev_proposed',
        path: ['jev_proposed'],
      });
    }
    if (value.jev_status !== 'evaluated' && !value.provisional) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'non-evaluated Jev results are provisional',
        path: ['provisional'],
      });
    }
  });

export type SentinelDecision = z.infer<typeof SentinelDecisionSchema>;

export const EnvRulesSchema = z
  .object({
    block: z.array(z.enum(SEVERITIES)).max(6),
    review: z.array(z.enum(SEVERITIES)).max(6),
    warn: z.array(z.enum(SEVERITIES)).max(6),
  })
  .strict();

export type EnvRules = z.infer<typeof EnvRulesSchema>;

export const AllowlistEntrySchema = z
  .object({
    rule_id: z.string().min(1).max(256).optional(),
    cve: z.string().min(1).max(64).optional(),
    fingerprint: z.string().min(1).max(128).optional(),
    path: z.string().min(1).max(256).optional(),
    id: z.string().min(1).max(256).optional(),
    owner: z.string().min(1).max(128),
    reason: z.string().min(8).max(500),
    expires_at: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/, 'expires_at must be YYYY-MM-DD'),
  })
  .strict()
  .superRefine((entry, ctx) => {
    if (!entry.rule_id && !entry.cve && !entry.fingerprint && !entry.path && !entry.id) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Allowlist entry needs rule_id, cve, fingerprint, path, or id',
      });
    }
  });

export type AllowlistEntry = z.infer<typeof AllowlistEntrySchema>;

export const AllowlistSchema = z
  .object({
    rule_ids: z.array(z.string().min(1).max(256)).max(500).default([]),
    cves: z.array(z.string().min(1).max(64)).max(500).default([]),
    fingerprints: z.array(z.string().min(1).max(128)).max(500).default([]),
    paths: z.array(z.string().min(1).max(256)).max(200).default([]),
    ids: z.array(z.string().min(1).max(256)).max(500).default([]),
    entries: z.array(AllowlistEntrySchema).max(500).default([]),
  })
  .strict();

export type Allowlist = z.infer<typeof AllowlistSchema>;

export const GatePolicySchema = z
  .object({
    id: z.string().min(1).max(128),
    block_secrets: z.boolean(),
    escalate_known_exploited: z.boolean(),
    escalate_poc: z.boolean(),
    environments: z
      .object({
        production: EnvRulesSchema,
        staging: EnvRulesSchema,
        development: EnvRulesSchema,
        test: EnvRulesSchema,
        unknown: EnvRulesSchema,
      })
      .strict(),
    allowlist: AllowlistSchema,
    exclude_paths: z.array(z.string().min(1).max(256)).max(200),
  })
  .strict();

export type GatePolicy = z.infer<typeof GatePolicySchema>;

const closed = (block: Severity[], review: Severity[] = [], warn: Severity[] = []): EnvRules => ({
  block,
  review,
  warn,
});

export const DEFAULT_POLICY: GatePolicy = {
  id: 'default-gate',
  block_secrets: true,
  escalate_known_exploited: true,
  escalate_poc: true,
  environments: {
    production: closed(['critical', 'high'], ['unknown'], ['medium']),
    staging: closed(['critical', 'high'], ['unknown'], ['medium']),
    development: closed(['critical'], ['high', 'unknown'], ['medium']),
    test: closed(['critical'], ['unknown'], ['high', 'medium']),
    unknown: closed(['critical', 'high'], ['medium', 'unknown'], []),
  },
  allowlist: { rule_ids: [], cves: [], fingerprints: [], paths: [], ids: [], entries: [] },
  exclude_paths: [],
};

function withoutUndefined<T extends Record<string, unknown>>(value: T): Partial<T> {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as Partial<T>;
}

export function resolvePolicy(partial?: Partial<GatePolicy> | null): GatePolicy {
  const clean = withoutUndefined((partial ?? {}) as Record<string, unknown>);
  const merged = {
    ...DEFAULT_POLICY,
    ...clean,
    environments: {
      ...DEFAULT_POLICY.environments,
      ...(partial?.environments ?? {}),
    },
    allowlist: {
      ...DEFAULT_POLICY.allowlist,
      ...withoutUndefined((partial?.allowlist ?? {}) as Record<string, unknown>),
    },
    exclude_paths: partial?.exclude_paths ?? DEFAULT_POLICY.exclude_paths,
  };
  return GatePolicySchema.parse(merged);
}

export const RunOptionsSchema = z.object({
  environment: z.enum(ENVIRONMENTS).default('production'),
  component: z.string().max(128).default(''),
  gate_scope: z.enum(GATE_SCOPES).default('all'),
  gate_mode: z.enum(GATE_MODES).default('all'),
  min_confidence: z.number().min(0).max(1).default(0.75),
  low_confidence_policy: z.enum(LOW_CONFIDENCE_POLICIES).default('fail'),
  source_error_policy: z.enum(SOURCE_ERROR_POLICIES).default('fail'),
  review_mode: z.enum(REVIEW_MODES).default('fail'),
  jev_provider: z.enum(JEV_PROVIDERS).default('vercel-ai-gateway'),
  jev_endpoint: z.string().optional(),
  jev_model: z.string().optional(),
  timeout_ms: z.number().int().positive().max(120_000).default(45_000),
  dry_run: z.boolean().default(false),
  comment_on_github: z.boolean().default(false),
  create_check_run: z.boolean().default(true),
  enrich_epss_kev: z.boolean().default(false),
  annotate: z.boolean().default(true),
  max_findings: z.number().int().positive().max(5000).default(2000),
  max_findings_to_jev: z.number().int().positive().max(100).default(40),
  changed_paths_unknown: z.boolean().default(false),
});

export type RunOptions = z.infer<typeof RunOptionsSchema>;

export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
}

export function environmentOrThrow(value: string | undefined, fallback: EnvironmentName): EnvironmentName {
  if (!value) return fallback;
  if (!(ENVIRONMENTS as readonly string[]).includes(value)) {
    throw new Error(`Unsupported environment: ${value}`);
  }
  return value as EnvironmentName;
}
