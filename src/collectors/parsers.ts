import type { RawFinding } from './common.js';
import {
  SourceParseError,
  asArray,
  asRecord,
  inferCategory,
  inferExploitability,
  makeRaw,
  normalizeSeverity,
  severityFromScore,
  text,
} from './common.js';

function findingsArray(data: unknown): unknown[] {
  if (Array.isArray(data)) return data;
  const record = asRecord(data);
  if (!record) throw new SourceParseError('normalized findings must be an array or { findings: [] }');
  if (!Array.isArray(record.findings)) {
    throw new SourceParseError('normalized document is missing findings[]');
  }
  return record.findings;
}

export function parseNormalized(data: unknown): RawFinding[] {
  return findingsArray(data).map((item, index) => {
    const record = asRecord(item);
    if (!record) {
      return makeRaw({
        source: 'normalized',
        category: 'other',
        severity: 'unknown',
        title: `Unparsed finding ${index + 1}`,
        ruleId: 'unparsed',
      });
    }
    const hints = [
      text(record.category),
      text(record.rule_id),
      text(record.ruleId),
      text(record.cve),
      text(record.title),
    ];
    const category = inferCategory(hints, 'other');
    const explicit = text(record.category).toLowerCase();
    const known = ['sast', 'sca', 'iac', 'secrets', 'container', 'license', 'other'] as const;
    const resolved = (known as readonly string[]).includes(explicit)
      ? (explicit as (typeof known)[number])
      : category;
    return makeRaw({
      source: 'normalized',
      category: resolved,
      severity: normalizeSeverity(record.severity),
      title: text(record.title) || text(record.message) || 'Normalized finding',
      ruleId: text(record.rule_id) || text(record.ruleId) || 'unknown',
      path: record.path,
      startLine: record.start_line ?? record.startLine,
      cve: text(record.cve) || null,
      exploitability: text(record.exploitability)
        ? inferExploitability([text(record.exploitability)])
        : inferExploitability(hints),
      message: text(record.message, 500),
      component: text(record.component),
      hideMessage: resolved === 'secrets',
      scannerSuppressed: record.suppressed === true,
    });
  });
}

export function parseSarif(data: unknown): RawFinding[] {
  const doc = asRecord(data);
  if (!doc || !Array.isArray(doc.runs)) {
    throw new SourceParseError('SARIF document is missing runs[]');
  }
  const findings: RawFinding[] = [];
  for (const run of doc.runs) {
    const runRecord = asRecord(run);
    if (!runRecord) continue;
    const driver = asRecord(asRecord(runRecord.tool)?.driver);
    const rules = new Map<string, Record<string, unknown>>();
    for (const rule of asArray(driver?.rules)) {
      const ruleRecord = asRecord(rule);
      const id = text(ruleRecord?.id);
      if (ruleRecord && id) rules.set(id, ruleRecord);
    }
    for (const result of asArray(runRecord.results)) {
      const record = asRecord(result) ?? {};
      const ruleId = text(record.ruleId) || text(record.ruleID) || 'unknown';
      const rule = rules.get(ruleId);
      const properties = asRecord(rule?.properties);
      const tags = asArray(properties?.tags).map(tag => text(tag));
      const score = Number(properties?.['security-severity']);
      const severity = Number.isFinite(score)
        ? severityFromScore(score)
        : normalizeSeverity(record.level ?? 'warning');
      const location = asRecord(asArray(record.locations)[0]);
      const physical = asRecord(location?.physicalLocation);
      const artifact = asRecord(physical?.artifactLocation);
      const region = asRecord(physical?.region);
      const message = asRecord(record.message);
      const category = inferCategory(
        [ruleId, ...tags, text(driver?.name)],
        tags.some(tag => /secret/i.test(tag)) ? 'secrets' : 'sast',
      );
      findings.push(
        makeRaw({
          source: 'sarif',
          category,
          severity,
          title:
            category === 'secrets'
              ? ruleId
              : text(message?.text) || text(rule?.shortDescription && asRecord(rule.shortDescription)?.text) || ruleId,
          ruleId,
          path: artifact?.uri,
          startLine: region?.startLine,
          message: text(message?.text, 500),
          hints: tags,
          hideMessage: category === 'secrets',
          scannerSuppressed: asArray(record.suppressions).length > 0,
        }),
      );
    }
  }
  return findings;
}

export function parseSemgrep(data: unknown): RawFinding[] {
  const doc = asRecord(data);
  if (!doc) throw new SourceParseError('Semgrep document must be an object');
  const rows = Array.isArray(doc.results)
    ? doc.results
    : Array.isArray(doc.findings)
      ? doc.findings
      : null;
  if (!rows) throw new SourceParseError('Semgrep document is missing results[] or findings[]');
  return rows.map(item => {
    const record = asRecord(item) ?? {};
    const extra = asRecord(record.extra);
    const metadata = asRecord(extra?.metadata);
    const start = asRecord(record.start);
    const location = asRecord(record.location);
    const rule = asRecord(record.rule);
    const ruleId =
      text(record.check_id) || text(record.rule_name) || text(rule?.id) || 'unknown';
    const category = inferCategory(
      [ruleId, text(metadata?.category), text(extra?.message)],
      'sast',
    );
    return makeRaw({
      source: 'semgrep',
      category,
      severity: normalizeSeverity(extra?.severity ?? record.severity ?? 'medium'),
      title: text(extra?.message) || text(rule?.message) || ruleId,
      ruleId,
      path: record.path ?? location?.file_path,
      startLine: start?.line ?? location?.line,
      message: text(extra?.message, 500) || text(rule?.message, 500),
      hints: [text(metadata?.cwe), text(metadata?.likelihood), text(metadata?.impact)],
      hideMessage: category === 'secrets',
    });
  });
}

export function parseTrivy(data: unknown): RawFinding[] {
  const doc = asRecord(data);
  if (!doc || !Array.isArray(doc.Results)) {
    throw new SourceParseError('Trivy document is missing Results[]');
  }
  const artifactType = text(doc.ArtifactType);
  const findings: RawFinding[] = [];
  for (const result of doc.Results) {
    const record = asRecord(result) ?? {};
    const target = text(record.Target);
    const clazz = text(record.Class);
    for (const vuln of asArray(record.Vulnerabilities)) {
      const item = asRecord(vuln) ?? {};
      const cve = text(item.VulnerabilityID) || null;
      const category = artifactType === 'container_image' || clazz === 'os-pkgs' ? 'container' : 'sca';
      findings.push(
        makeRaw({
          source: 'trivy',
          category,
          severity: normalizeSeverity(item.Severity),
          title: text(item.Title) || cve || 'Trivy vulnerability',
          ruleId: cve || text(item.PkgName) || 'trivy',
          path: target,
          cve,
          message: text(item.Description, 500),
          hints: [text(item.Severity), clazz, artifactType],
          component: text(item.PkgName),
        }),
      );
    }
    for (const misconfig of asArray(record.Misconfigurations)) {
      const item = asRecord(misconfig) ?? {};
      findings.push(
        makeRaw({
          source: 'trivy',
          category: 'iac',
          severity: normalizeSeverity(item.Severity),
          title: text(item.Title) || text(item.ID) || 'Trivy misconfiguration',
          ruleId: text(item.ID) || 'trivy-misconfig',
          path: target,
          startLine: item.CauseMetadata && asRecord(item.CauseMetadata)?.StartLine,
          message: text(item.Message, 500),
          hints: ['iac', 'misconfig'],
        }),
      );
    }
    for (const secret of asArray(record.Secrets)) {
      const item = asRecord(secret) ?? {};
      findings.push(
        makeRaw({
          source: 'trivy',
          category: 'secrets',
          severity: normalizeSeverity(item.Severity || 'critical'),
          title: text(item.Title) || text(item.RuleID) || 'Trivy secret',
          ruleId: text(item.RuleID) || 'trivy-secret',
          path: target,
          startLine: item.StartLine,
          hideMessage: true,
          hints: ['secret'],
        }),
      );
    }
    for (const license of asArray(record.Licenses)) {
      const item = asRecord(license) ?? {};
      findings.push(
        makeRaw({
          source: 'trivy',
          category: 'license',
          severity: normalizeSeverity(item.Severity || 'unknown'),
          title: text(item.Name) || 'License finding',
          ruleId: text(item.Name) || 'license',
          path: target,
          hints: ['license', text(item.Category)],
        }),
      );
    }
  }
  return findings;
}

export function parseSnyk(data: unknown): RawFinding[] {
  const doc = asRecord(data);
  if (!doc) throw new SourceParseError('Snyk document must be an object');
  if (Array.isArray(doc.vulnerabilities)) {
    return doc.vulnerabilities.map(item => {
      const record = asRecord(item) ?? {};
      const identifiers = asRecord(record.identifiers);
      const cves = asArray(identifiers?.CVE).map(cve => text(cve));
      return makeRaw({
        source: 'snyk',
        category: text(record.type) === 'license' ? 'license' : 'sca',
        severity: normalizeSeverity(record.severity),
        title: text(record.title) || text(record.id) || 'Snyk vulnerability',
        ruleId: text(record.id) || 'snyk',
        cve: cves[0] || null,
        component: text(record.packageName),
        message: text(record.description, 500),
        hints: [text(record.exploit), ...cves],
        scannerSuppressed: record.isIgnored === true,
      });
    });
  }
  if (Array.isArray(doc.data)) {
    return doc.data.map(item => {
      const record = asRecord(item) ?? {};
      const attributes = asRecord(record.attributes) ?? {};
      const problems = asArray(attributes.problems).map(problem => text(asRecord(problem)?.id));
      const issueType = text(attributes.type);
      const category =
        issueType.includes('license')
          ? 'license'
          : issueType.includes('code')
            ? 'sast'
            : issueType.includes('config')
              ? 'iac'
              : 'sca';
      const coordinates = asArray(attributes.coordinates);
      const first = asRecord(coordinates[0]);
      const representations = asArray(first?.representations);
      const dependency = asRecord(asRecord(representations[0])?.dependency);
      return makeRaw({
        source: 'snyk',
        category,
        severity: normalizeSeverity(attributes.effective_severity_level),
        title: text(attributes.title) || text(attributes.key) || 'Snyk issue',
        ruleId: text(attributes.key) || text(record.id) || 'snyk',
        component: text(dependency?.package_name),
        cve: problems.find(id => id.startsWith('CVE-')) || null,
        message: text(attributes.title, 500),
        hints: [issueType, ...problems],
        scannerSuppressed: attributes.status === 'ignored',
      });
    });
  }
  throw new SourceParseError('Snyk document is missing vulnerabilities[] or data[]');
}

export function parseVeracode(data: unknown): RawFinding[] {
  const doc = asRecord(data);
  if (!doc) throw new SourceParseError('Veracode document must be an object');
  const embedded = asRecord(doc._embedded);
  const rows = Array.isArray(doc.findings)
    ? doc.findings
    : Array.isArray(embedded?.findings)
      ? embedded.findings
      : null;
  if (!rows) throw new SourceParseError('Veracode document is missing findings[]');
  return rows.map(item => {
    const record = asRecord(item) ?? {};
    const cwe = asRecord(record.cwe);
    const details = asRecord(record.finding_details);
    const status = asRecord(record.finding_status);
    const severity = normalizeSeverity(record.severity);
    const ruleId = cwe?.id ? `CWE-${text(cwe.id)}` : text(record.issue_id) || 'veracode';
    return makeRaw({
      source: 'veracode',
      category: 'sast',
      severity,
      title: text(cwe?.name) || text(record.description) || ruleId,
      ruleId,
      path: details?.file_path,
      startLine: details?.file_line_number,
      message: text(record.description, 500),
      hints: [text(cwe?.name), text(status?.status)],
      scannerSuppressed: text(status?.status).toUpperCase() === 'MITIGATED',
    });
  });
}

export function parseCodeScanning(data: unknown): RawFinding[] {
  if (!Array.isArray(data)) throw new SourceParseError('code scanning alerts must be an array');
  return data.map(item => {
    const record = asRecord(item) ?? {};
    const rule = asRecord(record.rule);
    const instance = asRecord(record.most_recent_instance);
    const location = asRecord(instance?.location);
    const message = asRecord(instance?.message);
    const tool = asRecord(record.tool);
    const security = text(rule?.security_severity_level);
    return makeRaw({
      source: 'github-code-scanning',
      category: inferCategory([text(rule?.id), text(tool?.name)], 'sast'),
      severity: security ? normalizeSeverity(security) : normalizeSeverity(rule?.severity),
      title: text(rule?.description) || text(message?.text) || text(rule?.id) || 'Code scanning alert',
      ruleId: text(rule?.id) || 'code-scanning',
      path: location?.path,
      startLine: location?.start_line,
      message: text(message?.text, 500),
      hints: [text(tool?.name)],
      scannerSuppressed: text(record.state) === 'dismissed',
    });
  });
}

export function parseSecretScanning(data: unknown): RawFinding[] {
  if (!Array.isArray(data)) throw new SourceParseError('secret scanning alerts must be an array');
  return data.map(item => {
    const record = asRecord(item) ?? {};
    const locations = asArray(record.locations);
    const first = asRecord(locations[0]);
    const details = asRecord(first?.details);
    return makeRaw({
      source: 'github-secret-scanning',
      category: 'secrets',
      severity: 'critical',
      title: text(record.secret_type_display_name) || text(record.secret_type) || 'Secret scanning alert',
      ruleId: text(record.secret_type) || 'secret-scanning',
      path: details?.path,
      startLine: details?.start_line,
      hideMessage: true,
      scannerSuppressed: text(record.state) === 'resolved',
    });
  });
}

export function parseDependabot(data: unknown): RawFinding[] {
  if (!Array.isArray(data)) throw new SourceParseError('dependabot alerts must be an array');
  return data.map(item => {
    const record = asRecord(item) ?? {};
    const advisory = asRecord(record.security_advisory);
    const vulnerability = asRecord(record.security_vulnerability);
    const dependency = asRecord(record.dependency);
    const pkg = asRecord(dependency?.package);
    const manifest = text(dependency?.manifest_path);
    return makeRaw({
      source: 'github-dependabot',
      category: 'sca',
      severity: normalizeSeverity(vulnerability?.severity ?? advisory?.severity),
      title: text(advisory?.summary) || text(advisory?.ghsa_id) || 'Dependabot alert',
      ruleId: text(advisory?.ghsa_id) || text(record.number) || 'dependabot',
      path: manifest || null,
      cve: text(advisory?.cve_id) || null,
      component: text(pkg?.name),
      message: text(advisory?.summary, 500),
      hints: [text(advisory?.cve_id)],
      scannerSuppressed: text(record.state) === 'dismissed',
    });
  });
}

/** OSV scanner JSON (`results[].packages[].vulnerabilities[]` or top-level `vulns[]`). */
export function parseOsv(data: unknown): RawFinding[] {
  const doc = asRecord(data);
  if (!doc) throw new SourceParseError('OSV document must be an object');
  const findings: RawFinding[] = [];
  const results = asArray(doc.results);
  if (results.length > 0) {
    for (const result of results) {
      const resultRecord = asRecord(result) ?? {};
      const source = asRecord(resultRecord.source);
      const path = text(source?.path) || null;
      for (const pkg of asArray(resultRecord.packages)) {
        const pkgRecord = asRecord(pkg) ?? {};
        const packageInfo = asRecord(pkgRecord.package);
        for (const vuln of asArray(pkgRecord.vulnerabilities)) {
          const vulnRecord = asRecord(vuln) ?? {};
          const aliases = asArray(vulnRecord.aliases).map(alias => text(alias));
          const cve = aliases.find(alias => alias.startsWith('CVE-')) || null;
          const severityEntries = asArray(vulnRecord.severity);
          const firstSeverity = asRecord(severityEntries[0]);
          findings.push(
            makeRaw({
              source: 'osv',
              category: 'sca',
              severity: firstSeverity?.score
                ? severityFromScore(Number(firstSeverity.score))
                : normalizeSeverity(firstSeverity?.type),
              title: text(vulnRecord.summary) || text(vulnRecord.id) || 'OSV vulnerability',
              ruleId: text(vulnRecord.id) || 'osv',
              path,
              cve,
              component: text(packageInfo?.name),
              message: text(vulnRecord.details || vulnRecord.summary, 500),
              hints: aliases,
            }),
          );
        }
      }
    }
    return findings;
  }
  const vulns = asArray(doc.vulns);
  if (vulns.length === 0) throw new SourceParseError('OSV document is missing results[] or vulns[]');
  return vulns.map(item => {
    const record = asRecord(item) ?? {};
    const aliases = asArray(record.aliases).map(alias => text(alias));
    return makeRaw({
      source: 'osv',
      category: 'sca',
      severity: normalizeSeverity(record.severity),
      title: text(record.summary) || text(record.id) || 'OSV vulnerability',
      ruleId: text(record.id) || 'osv',
      cve: aliases.find(alias => alias.startsWith('CVE-')) || null,
      message: text(record.details || record.summary, 500),
      hints: aliases,
    });
  });
}

/** Grype JSON (`matches[]`). */
export function parseGrype(data: unknown): RawFinding[] {
  const doc = asRecord(data);
  if (!doc || !Array.isArray(doc.matches)) {
    throw new SourceParseError('Grype document is missing matches[]');
  }
  return doc.matches.map(item => {
    const record = asRecord(item) ?? {};
    const vulnerability = asRecord(record.vulnerability) ?? {};
    const artifact = asRecord(record.artifact) ?? {};
    const related = asArray(vulnerability.relatedVulnerabilities);
    const relatedCve = related
      .map(entry => text(asRecord(entry)?.id))
      .find(id => id.startsWith('CVE-'));
    return makeRaw({
      source: 'grype',
      category: 'sca',
      severity: normalizeSeverity(vulnerability.severity),
      title: text(vulnerability.description) || text(vulnerability.id) || 'Grype match',
      ruleId: text(vulnerability.id) || 'grype',
      path: text(artifact.name) ? `pkg:${text(artifact.name)}` : null,
      cve: text(vulnerability.id).startsWith('CVE-') ? text(vulnerability.id) : relatedCve || null,
      component: text(artifact.name),
      message: text(vulnerability.description, 500),
      hints: [text(vulnerability.id)],
    });
  });
}

/** Checkov JSON (`results.failed_checks[]` or top-level `failed_checks[]`). */
export function parseCheckov(data: unknown): RawFinding[] {
  const doc = asRecord(data);
  if (!doc) throw new SourceParseError('Checkov document must be an object');
  const results = asRecord(doc.results);
  const rows = Array.isArray(results?.failed_checks)
    ? results.failed_checks
    : Array.isArray(doc.failed_checks)
      ? doc.failed_checks
      : null;
  if (!rows) throw new SourceParseError('Checkov document is missing failed_checks[]');
  return rows.map(item => {
    const record = asRecord(item) ?? {};
    const fileLineRange = asArray(record.file_line_range);
    const startLine = fileLineRange[0];
    return makeRaw({
      source: 'checkov',
      category: 'iac',
      severity: normalizeSeverity(record.severity),
      title: text(record.check_name) || text(record.check_id) || 'Checkov finding',
      ruleId: text(record.check_id) || 'checkov',
      path: record.file_path ?? record.repo_file_path,
      startLine,
      message: text(record.check_name || record.description, 500),
      hints: [text(record.check_type), text(record.guideline)],
    });
  });
}
