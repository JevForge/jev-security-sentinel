import { describe, expect, it } from 'vitest';
import {
  parseCodeScanning,
  parseDependabot,
  parseNormalized,
  parseSarif,
  parseSecretScanning,
  parseSemgrep,
  parseSnyk,
  parseTrivy,
  parseVeracode,
  parseOsv,
  parseGrype,
  parseCheckov,
} from '../../src/collectors/parsers.js';
import { loadFindings } from '../../src/collectors/load.js';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('scanner normalizers', () => {
  it('parses SARIF severity, suppression, and paths', () => {
    const findings = parseSarif({
      runs: [
        {
          tool: {
            driver: {
              name: 'Example',
              rules: [
                {
                  id: 'SECRET001',
                  properties: { 'security-severity': '9.2', tags: ['secret'] },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'SECRET001',
              level: 'error',
              message: { text: 'token ghp_abcdefghijklmnopqrstuvwxyz123456' },
              suppressions: [{ kind: 'inSource' }],
              locations: [
                { physicalLocation: { artifactLocation: { uri: 'src/app.ts' }, region: { startLine: 3 } } },
              ],
            },
          ],
        },
      ],
    });
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.category).toBe('secrets');
    expect(findings[0]?.scanner_suppressed).toBe(true);
    expect(findings[0]?.message).toBe('');
    expect(findings[0]?.title).not.toContain('ghp_');
  });

  it('parses Semgrep, Trivy, Snyk, and Veracode reports', () => {
    expect(parseSemgrep({
      results: [
        {
          check_id: 'javascript.eval',
          path: 'src/app.js',
          start: { line: 4 },
          extra: { severity: 'ERROR', message: 'eval detected', metadata: { cwe: 'CWE-95' } },
        },
      ],
    })[0]).toMatchObject({ source: 'semgrep', severity: 'high', path: 'src/app.js' });

    const trivy = parseTrivy({
      ArtifactType: 'container_image',
      Results: [
        {
          Target: 'app/package.json',
          Class: 'os-pkgs',
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-2024-0001', PkgName: 'openssl', Severity: 'CRITICAL', Title: 'openssl' },
          ],
          Misconfigurations: [{ ID: 'DS001', Title: 'root user', Severity: 'HIGH', Message: 'running as root' }],
          Secrets: [{ RuleID: 'aws-access-key', Title: 'AWS', Severity: 'CRITICAL', StartLine: 2, Match: 'AKIASECRETVALUE123456' }],
          Licenses: [{ Name: 'GPL-3.0', Severity: 'MEDIUM' }],
        },
      ],
    });
    expect(trivy.map(item => item.category)).toEqual(['container', 'iac', 'secrets', 'license']);
    expect(JSON.stringify(trivy)).not.toContain('AKIASECRETVALUE123456');

    expect(parseSnyk({
      vulnerabilities: [
        {
          id: 'SNYK-JS-LODASH-1',
          title: 'Prototype Pollution',
          severity: 'high',
          packageName: 'lodash',
          exploit: 'Proof of Concept',
          identifiers: { CVE: ['CVE-2020-8203'] },
        },
      ],
    })[0]).toMatchObject({ cve: 'CVE-2020-8203', exploitability: 'poc', component: 'lodash' });

    expect(parseSnyk({
      data: [
        {
          id: 'issue-1',
          attributes: {
            title: 'SQL injection',
            effective_severity_level: 'critical',
            type: 'code',
            key: 'SNYK-CODE-1',
            status: 'open',
            problems: [{ id: 'CWE-89' }],
          },
        },
      ],
    })[0]?.category).toBe('sast');

    expect(parseVeracode({
      _embedded: {
        findings: [
          {
            issue_id: 9,
            severity: 5,
            cwe: { id: 89, name: 'SQL Injection' },
            finding_status: { status: 'OPEN' },
            description: 'query concatenation',
            finding_details: { file_path: 'src/db.ts', file_line_number: 12 },
          },
        ],
      },
    })[0]).toMatchObject({ severity: 'critical', rule_id: 'CWE-89', path: 'src/db.ts' });
  });

  it('parses GitHub Advanced Security alerts without copying secret values', () => {
    const secret = parseSecretScanning([
      {
        number: 2,
        state: 'open',
        secret_type: 'slack_webhook',
        secret_type_display_name: 'Slack webhook',
        secret: 'https://hooks.slack.com/services/SUPERSECRET',
      },
    ]);
    expect(JSON.stringify(secret)).not.toContain('SUPERSECRET');
    expect(secret[0]?.category).toBe('secrets');

    expect(parseCodeScanning([
      {
        state: 'open',
        rule: { id: 'js/sql-injection', severity: 'error', security_severity_level: 'high' },
        most_recent_instance: {
          location: { path: 'src/a.js', start_line: 3 },
          message: { text: 'user input in query' },
        },
        tool: { name: 'CodeQL' },
      },
    ])[0]).toMatchObject({ source: 'github-code-scanning', severity: 'high', path: 'src/a.js' });

    expect(parseDependabot([
      {
        state: 'open',
        security_advisory: { ghsa_id: 'GHSA-1', summary: 'lodash issue', cve_id: 'CVE-2024-9999', severity: 'high' },
        dependency: { package: { name: 'lodash' }, manifest_path: 'package.json' },
        security_vulnerability: { severity: 'high' },
      },
    ])[0]).toMatchObject({ source: 'github-dependabot', cve: 'CVE-2024-9999', path: 'package.json' });
  });

  it('accepts sparse and alternate scanner shapes', () => {
    expect(parseSarif({ runs: [null, { tool: { driver: { rules: [null, { id: 'R' }] } }, results: [null, { level: 'note' }] }] })).toHaveLength(2);
    expect(parseSemgrep({
      findings: [{ rule: { id: 'api.rule', message: 'msg' }, location: { file_path: 'a.ts', line: 2 }, severity: 'INFO' }],
    })[0]?.rule_id).toBe('api.rule');
    expect(parseTrivy({ Results: [null, {}] })).toEqual([]);
    expect(parseSnyk({ vulnerabilities: [{ type: 'license', isIgnored: true, severity: 'low', id: 'L' }] })[0]?.category).toBe('license');
    expect(parseSnyk({
      data: [{ attributes: { type: 'config', status: 'ignored', title: 'cfg', effective_severity_level: 'low', key: 'C' } }],
    })[0]).toMatchObject({ category: 'iac', scanner_suppressed: true });
    expect(parseVeracode({
      findings: [{ severity: 2, finding_status: { status: 'MITIGATED' }, description: 'mitigated' }],
    })[0]?.scanner_suppressed).toBe(true);
    expect(parseCodeScanning([{ state: 'dismissed', rule: { id: 'r', severity: 'warning' } }])[0]?.scanner_suppressed).toBe(true);
    expect(parseSecretScanning([{ state: 'resolved', secret_type: 'aws' }])[0]?.scanner_suppressed).toBe(true);
    expect(parseDependabot([{ state: 'dismissed' }])[0]?.scanner_suppressed).toBe(true);
    expect(parseOsv({
      results: [{
        source: { path: 'go.mod' },
        packages: [{
          package: { name: 'github.com/foo/bar' },
          vulnerabilities: [{ id: 'OSV-1', aliases: ['CVE-2024-1'], summary: 'bug', severity: [{ score: '9.1' }] }],
        }],
      }],
    })[0]).toMatchObject({ source: 'osv', category: 'sca', cve: 'CVE-2024-1' });
    expect(parseGrype({
      matches: [{ vulnerability: { id: 'CVE-2024-2', severity: 'High', description: 'x' }, artifact: { name: 'openssl' } }],
    })[0]).toMatchObject({ source: 'grype', component: 'openssl' });
    expect(parseCheckov({
      results: { failed_checks: [{ check_id: 'CKV_1', check_name: 'root', severity: 'HIGH', file_path: 'Dockerfile', file_line_range: [1] }] },
    })[0]).toMatchObject({ source: 'checkov', category: 'iac', path: 'Dockerfile' });
    expect(parseNormalized([{ severity: 'critical', category: 'secrets', exploitability: 'unlikely', title: 'tok', rule_id: 'S' }])[0]?.message).toBe('');
    expect(() => parseSemgrep({})).toThrow(/results/);
    expect(() => parseSnyk({})).toThrow(/vulnerabilities/);
    expect(() => parseVeracode({})).toThrow(/findings/);
    expect(() => parseSarif({})).toThrow(/runs/);
    expect(() => parseCodeScanning({})).toThrow(/array/);
  });

  it('preserves a placeholder when a normalized item is malformed', () => {
    const findings = parseNormalized({ findings: ['nope', { severity: 'medium', title: 'real', rule_id: 'R1', category: 'iac' }] });
    expect(findings).toHaveLength(2);
    expect(findings[1]).toMatchObject({ category: 'iac', severity: 'medium' });
  });

  it('loads reports from the workspace and rejects paths that escape it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sentinel-'));
    writeFileSync(join(dir, 'findings.json'), JSON.stringify([{ title: 'one', severity: 'low', rule_id: 'R', category: 'sast' }]));
    const loaded = loadFindings({
      workspace: dir,
      normalizedPath: 'findings.json',
      sarifPath: '../outside.sarif',
      maxFindings: 10,
    });
    expect(loaded.findings).toHaveLength(1);
    expect(loaded.errors.some(error => error.message.includes('escapes'))).toBe(true);
  });
});
