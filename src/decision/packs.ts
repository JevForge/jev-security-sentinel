import type { EnvRules, GatePolicy } from '../schemas/sentinel.js';
import { DEFAULT_POLICY, resolvePolicy } from '../schemas/sentinel.js';
import type { Severity } from '../schemas/enums.js';

export const POLICY_PACKS = ['default', 'strict-prod', 'startup', 'compliance'] as const;
export type PolicyPack = (typeof POLICY_PACKS)[number];

const closed = (block: Severity[], review: Severity[] = [], warn: Severity[] = []): EnvRules => ({
  block,
  review,
  warn,
});

const PACKS: Record<PolicyPack, Partial<GatePolicy>> = {
  default: {},
  'strict-prod': {
    id: 'pack:strict-prod',
    block_secrets: true,
    escalate_known_exploited: true,
    escalate_poc: true,
    environments: {
      production: closed(['critical', 'high', 'medium'], ['unknown', 'low'], []),
      staging: closed(['critical', 'high', 'medium'], ['unknown'], ['low']),
      development: closed(['critical', 'high'], ['medium', 'unknown'], ['low']),
      test: closed(['critical', 'high'], ['unknown'], ['medium']),
      unknown: closed(['critical', 'high', 'medium'], ['unknown'], []),
    },
  },
  startup: {
    id: 'pack:startup',
    block_secrets: true,
    escalate_known_exploited: true,
    escalate_poc: false,
    environments: {
      production: closed(['critical'], ['high', 'unknown'], ['medium']),
      staging: closed(['critical'], ['high', 'unknown'], ['medium']),
      development: closed(['critical'], ['unknown'], ['high', 'medium']),
      test: closed([], ['critical', 'unknown'], ['high', 'medium']),
      unknown: closed(['critical'], ['high', 'unknown'], ['medium']),
    },
  },
  compliance: {
    id: 'pack:compliance',
    block_secrets: true,
    escalate_known_exploited: true,
    escalate_poc: true,
    environments: {
      production: closed(['critical', 'high'], ['medium', 'unknown'], ['low']),
      staging: closed(['critical', 'high'], ['medium', 'unknown'], ['low']),
      development: closed(['critical', 'high'], ['medium', 'unknown'], []),
      test: closed(['critical', 'high'], ['medium', 'unknown'], []),
      unknown: closed(['critical', 'high'], ['medium', 'unknown'], ['low']),
    },
  },
};

export function resolvePolicyPack(
  pack: PolicyPack | undefined,
  overrides?: Partial<GatePolicy> | null,
): GatePolicy {
  const base = PACKS[pack ?? 'default'] ?? {};
  const merged = resolvePolicy({
    ...base,
    ...withoutUndefined(overrides ?? {}),
    id: overrides?.id ?? base.id ?? DEFAULT_POLICY.id,
    environments: {
      ...DEFAULT_POLICY.environments,
      ...(base.environments ?? {}),
      ...(overrides?.environments ?? {}),
    },
    allowlist: {
      ...DEFAULT_POLICY.allowlist,
      ...(base.allowlist ?? {}),
      ...(overrides?.allowlist ?? {}),
    },
    exclude_paths: overrides?.exclude_paths ?? base.exclude_paths ?? DEFAULT_POLICY.exclude_paths,
  });
  return merged;
}

function withoutUndefined<T extends Record<string, unknown>>(value: T): Partial<T> {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as Partial<T>;
}
