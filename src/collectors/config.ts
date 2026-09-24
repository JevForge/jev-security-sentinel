import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import YAML from 'yaml';
import { z } from 'zod';
import {
  ENVIRONMENTS,
  GATE_SCOPES,
  JEV_PROVIDERS,
  LOW_CONFIDENCE_POLICIES,
  REVIEW_MODES,
  SOURCE_ERROR_POLICIES,
  type EnvironmentName,
  type GateScope,
  type JevProviderId,
  type LowConfidencePolicy,
  type ReviewMode,
  type SourceErrorPolicy,
} from '../schemas/enums.js';
import { AllowlistSchema, resolvePolicy, type GatePolicy } from '../schemas/sentinel.js';

const FileConfigSchema = z
  .object({
    jev_provider: z.enum(JEV_PROVIDERS).optional(),
    jev_endpoint: z.string().optional(),
    jev_model: z.string().optional(),
    min_confidence: z.number().min(0).max(1).optional(),
    low_confidence_policy: z.enum(LOW_CONFIDENCE_POLICIES).optional(),
    source_error_policy: z.enum(SOURCE_ERROR_POLICIES).optional(),
    review_mode: z.enum(REVIEW_MODES).optional(),
    environment: z.enum(ENVIRONMENTS).optional(),
    component: z.string().max(128).optional(),
    gate_scope: z.enum(GATE_SCOPES).optional(),
    block_secrets: z.boolean().optional(),
    escalate_known_exploited: z.boolean().optional(),
    escalate_poc: z.boolean().optional(),
    allowlist: AllowlistSchema.partial().optional(),
    exclude_paths: z.array(z.string()).optional(),
    policy_id: z.string().optional(),
    comment_on_github: z.boolean().optional(),
    annotate: z.boolean().optional(),
    max_findings: z.number().int().positive().max(5000).optional(),
    max_findings_to_jev: z.number().int().positive().max(100).optional(),
  })
  .strict();

export type FileConfig = z.infer<typeof FileConfigSchema>;

export function loadFileConfig(workspace: string, relativePath = '.jev/config.yml'): FileConfig {
  const full = resolve(workspace, relativePath);
  if (!existsSync(full)) return {};
  const raw = YAML.parse(readFileSync(full, 'utf8')) ?? {};
  return FileConfigSchema.parse(raw);
}

export function policyFromConfig(config: FileConfig): GatePolicy {
  return resolvePolicy({
    id: config.policy_id,
    block_secrets: config.block_secrets,
    escalate_known_exploited: config.escalate_known_exploited,
    escalate_poc: config.escalate_poc,
    allowlist: config.allowlist
      ? {
          rule_ids: config.allowlist.rule_ids ?? [],
          cves: config.allowlist.cves ?? [],
          fingerprints: config.allowlist.fingerprints ?? [],
          paths: config.allowlist.paths ?? [],
          ids: config.allowlist.ids ?? [],
        }
      : undefined,
    exclude_paths: config.exclude_paths,
  });
}

export function pickEnum<T extends string>(
  input: string | undefined,
  fallback: T | undefined,
  allowed: readonly T[],
  name: string,
): T {
  const value = (input || fallback || allowed[0]) as T;
  if (!allowed.includes(value)) throw new Error(`Unsupported ${name}: ${value}`);
  return value;
}

export function coalesceProvider(input: string | undefined, config: FileConfig): JevProviderId {
  return pickEnum(input, config.jev_provider, JEV_PROVIDERS, 'jev_provider');
}

export function coalescePolicy(input: string | undefined, config: FileConfig): LowConfidencePolicy {
  return pickEnum(input, config.low_confidence_policy, LOW_CONFIDENCE_POLICIES, 'low_confidence_policy');
}

export function coalesceEnvironment(input: string | undefined, config: FileConfig): EnvironmentName {
  return pickEnum(input, config.environment ?? 'production', ENVIRONMENTS, 'environment');
}

export function coalesceScope(input: string | undefined, config: FileConfig, fallback: GateScope): GateScope {
  return pickEnum(input, config.gate_scope ?? fallback, GATE_SCOPES, 'gate_scope');
}

export function coalesceReviewMode(input: string | undefined, config: FileConfig): ReviewMode {
  return pickEnum(input, config.review_mode, REVIEW_MODES, 'review_mode');
}

export function coalesceSourceErrors(input: string | undefined, config: FileConfig): SourceErrorPolicy {
  return pickEnum(input, config.source_error_policy, SOURCE_ERROR_POLICIES, 'source_error_policy');
}
