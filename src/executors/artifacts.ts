import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, SentinelDecision } from '../schemas/sentinel.js';
import { prioritizeFindings } from '../decision/prioritize.js';

function sarifLevel(finding: Finding): 'error' | 'warning' | 'note' {
  if (finding.gate_effect === 'blocking' || finding.severity === 'critical' || finding.severity === 'high') {
    return 'error';
  }
  if (finding.gate_effect === 'review' || finding.severity === 'medium') return 'warning';
  return 'note';
}

export function buildSarif(decision: SentinelDecision): object {
  const results = decision.findings.map(finding => {
    const location =
      finding.path != null
        ? {
            physicalLocation: {
              artifactLocation: { uri: finding.path.replace(/\\/g, '/') },
              ...(finding.start_line
                ? { region: { startLine: finding.start_line } }
                : {}),
            },
          }
        : undefined;
    return {
      ruleId: finding.rule_id,
      level: sarifLevel(finding),
      message: { text: `${finding.severity} ${finding.category}: ${finding.title}`.slice(0, 400) },
      properties: {
        fingerprint: finding.fingerprint,
        gate_effect: finding.gate_effect,
        cve: finding.cve,
        kev: finding.kev,
        epss: finding.epss,
        source: finding.source,
      },
      ...(location ? { locations: [location] } : {}),
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'JEV Security Sentinel',
            informationUri: 'https://github.com/JevForge/jev-security-sentinel',
            rules: [],
          },
        },
        results,
      },
    ],
  };
}

export function buildMarkdownReport(decision: SentinelDecision): string {
  const top = prioritizeFindings(decision.findings).slice(0, 25);
  const lines = [
    '# JEV Security Sentinel report',
    '',
    `- Decision: \`${decision.decision}\``,
    `- Policy floor: \`${decision.policy_floor}\``,
    `- Jev: \`${decision.jev_proposed ?? decision.jev_status}\` (confidence ${decision.confidence.toFixed(3)})`,
    `- Findings: ${decision.risk_summary.total} total / ${decision.risk_summary.blocking} blocking`,
    `- Reasons: ${decision.reason_codes.join(', ') || 'none'}`,
    '',
    '| Severity | Category | Rule | Path | Gate |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const finding of top) {
    const path = finding.path
      ? `${finding.path}${finding.start_line ? `:${finding.start_line}` : ''}`
      : 'n/a';
    lines.push(
      `| ${finding.severity} | ${finding.category} | ${finding.rule_id.replaceAll('|', '/')} | ${path.replaceAll('|', '/')} | ${finding.gate_effect} |`,
    );
  }
  lines.push('', '_Every collected finding stays visible. Allowlisting changes the gate effect only._');
  return lines.join('\n');
}

export function writeArtifactReports(input: {
  workspace: string;
  decision: SentinelDecision;
  writeSarif: boolean;
  writeMarkdown: boolean;
  writeJson: boolean;
}): { sarifPath: string | null; markdownPath: string | null; jsonPath: string | null } {
  const dir = join(input.workspace, '.jev');
  mkdirSync(dir, { recursive: true });
  let sarifPath: string | null = null;
  let markdownPath: string | null = null;
  let jsonPath: string | null = null;
  if (input.writeSarif) {
    sarifPath = join(dir, 'security-sentinel.sarif');
    writeFileSync(sarifPath, JSON.stringify(buildSarif(input.decision), null, 2));
  }
  if (input.writeMarkdown) {
    markdownPath = join(dir, 'security-sentinel-report.md');
    writeFileSync(markdownPath, buildMarkdownReport(input.decision));
  }
  if (input.writeJson) {
    jsonPath = join(dir, 'security-sentinel-report.json');
    writeFileSync(jsonPath, JSON.stringify(input.decision, null, 2));
  }
  return { sarifPath, markdownPath, jsonPath };
}
