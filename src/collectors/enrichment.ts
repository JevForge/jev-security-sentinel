import type { SourceError } from '../schemas/sentinel.js';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';

export interface EnrichmentMaps {
  kev: Set<string>;
  epss: Map<string, number>;
}

export interface EnrichmentClient {
  fetchJson(url: string, timeoutMs: number): Promise<unknown>;
}

async function defaultFetchJson(url: string, timeoutMs: number): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json', 'User-Agent': 'jev-security-sentinel' },
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return (await response.json()) as unknown;
  } finally {
    clearTimeout(timer);
  }
}

function normalizeCve(value: string): string {
  return value.trim().toUpperCase();
}

export function parseKevCatalog(data: unknown): Set<string> {
  const kev = new Set<string>();
  const root = data && typeof data === 'object' ? (data as Record<string, unknown>) : null;
  const vulnerabilities = Array.isArray(root?.vulnerabilities) ? root.vulnerabilities : [];
  for (const item of vulnerabilities) {
    if (!item || typeof item !== 'object') continue;
    const cve = (item as Record<string, unknown>).cveID;
    if (typeof cve === 'string' && cve.trim()) kev.add(normalizeCve(cve));
  }
  return kev;
}

export function parseEpssResponse(data: unknown): Map<string, number> {
  const scores = new Map<string, number>();
  const root = data && typeof data === 'object' ? (data as Record<string, unknown>) : null;
  const rows = Array.isArray(root?.data) ? root.data : [];
  for (const item of rows) {
    if (!item || typeof item !== 'object') continue;
    const row = item as Record<string, unknown>;
    const cve = typeof row.cve === 'string' ? normalizeCve(row.cve) : '';
    const epss = typeof row.epss === 'string' || typeof row.epss === 'number' ? Number(row.epss) : NaN;
    if (cve && Number.isFinite(epss) && epss >= 0 && epss <= 1) scores.set(cve, epss);
  }
  return scores;
}

/** Split CVEs into EPSS query batches (API URL length safety). */
export function chunkCves(cves: string[], size = 40): string[][] {
  const unique = [...new Set(cves.map(normalizeCve).filter(Boolean))];
  const batches: string[][] = [];
  for (let i = 0; i < unique.length; i += size) batches.push(unique.slice(i, i + size));
  return batches;
}

export async function loadEnrichmentMaps(input: {
  cves: string[];
  timeoutMs: number;
  client?: EnrichmentClient;
}): Promise<{ maps: EnrichmentMaps; errors: SourceError[] }> {
  const errors: SourceError[] = [];
  const client = input.client ?? { fetchJson: defaultFetchJson };
  const maps: EnrichmentMaps = { kev: new Set(), epss: new Map() };
  const cves = [...new Set(input.cves.map(normalizeCve).filter(Boolean))];
  if (cves.length === 0) return { maps, errors };

  try {
    maps.kev = parseKevCatalog(await client.fetchJson(KEV_URL, input.timeoutMs));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    errors.push({ source: 'cisa-kev', message: message.slice(0, 180) });
  }

  for (const batch of chunkCves(cves)) {
    const url = `${EPSS_URL}?cve=${batch.map(encodeURIComponent).join(',')}`;
    try {
      const parsed = parseEpssResponse(await client.fetchJson(url, input.timeoutMs));
      for (const [cve, score] of parsed) maps.epss.set(cve, score);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push({ source: 'epss', message: message.slice(0, 180) });
      break;
    }
  }

  return { maps, errors };
}

export function applyEnrichment(
  cve: string | null,
  exploitability: string,
  maps: EnrichmentMaps,
): { exploitability: string; epss: number | null; kev: boolean } {
  if (!cve) return { exploitability, epss: null, kev: false };
  const key = normalizeCve(cve);
  const kev = maps.kev.has(key);
  const epss = maps.epss.get(key) ?? null;
  let next = exploitability;
  if (kev) next = 'known_exploited';
  else if (epss !== null && epss >= 0.5 && exploitability === 'unknown') next = 'likely';
  return { exploitability: next, epss, kev };
}
