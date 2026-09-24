import { describe, expect, it } from 'vitest';
import {
  applyEnrichment,
  chunkCves,
  parseEpssResponse,
  parseKevCatalog,
  loadEnrichmentMaps,
} from '../../src/collectors/enrichment.js';
import { annotateFindings } from '../../src/decision/annotate.js';
import { DEFAULT_POLICY } from '../../src/schemas/sentinel.js';
import type { RawFinding } from '../../src/collectors/common.js';

describe('EPSS / KEV enrichment', () => {
  it('parses KEV and EPSS payloads', () => {
    const kev = parseKevCatalog({
      vulnerabilities: [{ cveID: 'CVE-2024-1234' }, { cveID: 'cve-2024-9999' }],
    });
    expect(kev.has('CVE-2024-1234')).toBe(true);
    expect(kev.has('CVE-2024-9999')).toBe(true);

    const epss = parseEpssResponse({
      data: [{ cve: 'CVE-2024-1234', epss: '0.81234' }, { cve: 'CVE-2024-0001', epss: 0.01 }],
    });
    expect(epss.get('CVE-2024-1234')).toBeCloseTo(0.81234);
    expect(chunkCves(['CVE-1', 'CVE-1', 'CVE-2'], 1)).toEqual([['CVE-1'], ['CVE-2']]);
  });

  it('marks KEV CVEs as known_exploited and attaches EPSS', () => {
    const maps = {
      kev: new Set(['CVE-2024-1111']),
      epss: new Map([['CVE-2024-1111', 0.77]]),
    };
    expect(applyEnrichment('CVE-2024-1111', 'unknown', maps)).toEqual({
      exploitability: 'known_exploited',
      epss: 0.77,
      kev: true,
    });

    const row: RawFinding = {
      source: 'trivy',
      category: 'sca',
      severity: 'high',
      title: 'openssl',
      rule_id: 'CVE-2024-1111',
      path: 'package.json',
      start_line: null,
      cve: 'CVE-2024-1111',
      exploitability: 'unknown',
      message: '',
      component: 'openssl',
      scanner_suppressed: false,
    };
    const findings = annotateFindings({
      raw: [row],
      policy: DEFAULT_POLICY,
      environment: 'production',
      component: '',
      gateScope: 'all',
      changedPaths: null,
      enrichment: maps,
    });
    expect(findings[0]?.kev).toBe(true);
    expect(findings[0]?.epss).toBeCloseTo(0.77);
    expect(findings[0]?.exploitability).toBe('known_exploited');
    expect(findings[0]?.gate_effect).toBe('blocking');
  });

  it('loads enrichment maps through the injected client', async () => {
    const result = await loadEnrichmentMaps({
      cves: ['CVE-2024-1111'],
      timeoutMs: 1000,
      client: {
        async fetchJson(url) {
          if (url.includes('known_exploited')) {
            return { vulnerabilities: [{ cveID: 'CVE-2024-1111' }] };
          }
          return { data: [{ cve: 'CVE-2024-1111', epss: 0.9 }] };
        },
      },
    });
    expect(result.errors).toEqual([]);
    expect(result.maps.kev.has('CVE-2024-1111')).toBe(true);
    expect(result.maps.epss.get('CVE-2024-1111')).toBe(0.9);
  });
});
