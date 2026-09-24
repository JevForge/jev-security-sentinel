import type { EnvironmentName, Exploitability, GateEffect, GateScope, Severity } from '../schemas/enums.js';
import type { Finding, GatePolicy } from '../schemas/sentinel.js';
import type { RawFinding } from '../collectors/common.js';
import { fingerprint } from '../utils/fingerprint.js';
import { matchesAnyGlob } from '../utils/glob.js';

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 2,
  info: 1,
};

function effectForSeverity(
  severity: Severity,
  policy: GatePolicy,
  environment: EnvironmentName,
): GateEffect {
  const rules = policy.environments[environment];
  if (rules.block.includes(severity)) return 'blocking';
  if (rules.review.includes(severity)) return 'review';
  if (rules.warn.includes(severity)) return 'warning';
  return 'informational';
}

function escalate(
  effect: GateEffect,
  exploitability: Exploitability,
  severity: Severity,
  policy: GatePolicy,
): GateEffect {
  if (policy.escalate_known_exploited && exploitability === 'known_exploited') {
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK.medium || severity === 'unknown') return 'blocking';
    return effect === 'informational' ? 'review' : effect;
  }
  if (policy.escalate_poc && exploitability === 'poc') {
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK.high) return 'blocking';
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK.medium) return effect === 'blocking' ? effect : 'review';
  }
  return effect;
}

export function pathInChange(filePath: string | null, changed: string[] | null): boolean {
  if (!changed) return true;
  if (!filePath) return true;
  const norm = filePath.replace(/\\/g, '/');
  return changed.some(candidate => {
    const item = candidate.replace(/\\/g, '/').replace(/^\.\//, '');
    return norm === item || norm.endsWith(`/${item}`) || item.endsWith(`/${norm}`);
  });
}

export function annotateFindings(input: {
  raw: RawFinding[];
  policy: GatePolicy;
  environment: EnvironmentName;
  component: string;
  gateScope: GateScope;
  changedPaths: string[] | null;
}): Finding[] {
  const seen = new Map<string, number>();
  return input.raw.map(raw => {
    const exploitability: Exploitability =
      raw.category === 'secrets' && raw.exploitability === 'unknown' ? 'likely' : raw.exploitability;
    const baseId = fingerprint([
      raw.source,
      raw.rule_id,
      raw.path,
      raw.start_line,
      raw.cve,
      raw.title,
    ]);
    const count = seen.get(baseId) ?? 0;
    seen.set(baseId, count + 1);
    const id = `${raw.source}:${count === 0 ? baseId : `${baseId}:${count}`}`;
    const excluded = matchesAnyGlob(input.policy.exclude_paths, raw.path);
    const allowlisted =
      raw.scanner_suppressed ||
      input.policy.allowlist.rule_ids.includes(raw.rule_id) ||
      input.policy.allowlist.ids.includes(id) ||
      input.policy.allowlist.fingerprints.includes(baseId) ||
      (raw.cve
        ? input.policy.allowlist.cves.some(cve => cve.toUpperCase() === raw.cve?.toUpperCase())
        : false) ||
      matchesAnyGlob(input.policy.allowlist.paths, raw.path);
    const inChange = pathInChange(raw.path, input.changedPaths);
    const outOfScope = excluded || (input.gateScope === 'changed' && !inChange);
    let gateEffect: GateEffect = 'informational';
    if (allowlisted) gateEffect = 'allowlisted';
    else if (outOfScope) gateEffect = 'out_of_scope';
    else if (raw.category === 'secrets' && input.policy.block_secrets) gateEffect = 'blocking';
    else {
      gateEffect = escalate(
        effectForSeverity(raw.severity, input.policy, input.environment),
        exploitability,
        raw.severity,
        input.policy,
      );
    }
    return {
      id,
      fingerprint: baseId,
      source: raw.source,
      category: raw.category,
      severity: raw.severity,
      title: raw.title,
      rule_id: raw.rule_id,
      path: raw.path,
      start_line: raw.start_line,
      component: raw.component || input.component,
      environment: input.environment,
      cve: raw.cve,
      exploitability,
      in_change: inChange,
      allowlisted,
      excluded,
      gate_effect: gateEffect,
      message: raw.message,
    };
  });
}
