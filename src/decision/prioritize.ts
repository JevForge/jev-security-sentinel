import type { Severity } from '../schemas/enums.js';
import type { Finding } from '../schemas/sentinel.js';

const SEVERITY_SCORE: Record<Severity, number> = {
  critical: 100,
  high: 80,
  medium: 50,
  low: 20,
  unknown: 40,
  info: 5,
};

const EXPLOIT_SCORE = {
  known_exploited: 40,
  poc: 25,
  likely: 15,
  unknown: 0,
  unlikely: -10,
} as const;

export function priorityScore(finding: Finding): number {
  let score = SEVERITY_SCORE[finding.severity] + EXPLOIT_SCORE[finding.exploitability];
  if (finding.in_change) score += 15;
  if (finding.category === 'secrets') score += 20;
  if (finding.environment === 'production') score += 10;
  if (finding.gate_effect === 'blocking') score += 30;
  if (finding.allowlisted || finding.excluded) score -= 50;
  return score;
}

export function prioritizeFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const delta = priorityScore(b) - priorityScore(a);
    if (delta !== 0) return delta;
    return a.id.localeCompare(b.id);
  });
}

export interface JevFindingSample {
  id: string;
  category: Finding['category'];
  severity: Finding['severity'];
  exploitability: Finding['exploitability'];
  rule_id: string;
  path: string | null;
  cve: string | null;
  in_change: boolean;
  gate_effect: Finding['gate_effect'];
  title: string;
}

export function sampleForJev(findings: Finding[], limit: number): JevFindingSample[] {
  return prioritizeFindings(findings)
    .slice(0, limit)
    .map(finding => ({
      id: finding.id,
      category: finding.category,
      severity: finding.severity,
      exploitability: finding.exploitability,
      rule_id: finding.rule_id,
      path: finding.path,
      cve: finding.cve,
      in_change: finding.in_change,
      gate_effect: finding.gate_effect,
      title: finding.category === 'secrets' ? finding.rule_id : finding.title,
    }));
}
