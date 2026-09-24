import { veracodeAuthorizationHeader } from '../integrations/veracode-hmac.js';
import { redactSecrets } from '../utils/sanitize.js';

export interface RemoteFetchOptions {
  fetchImpl?: typeof fetch;
  timeoutMs: number;
}

async function fetchJson(
  url: string,
  headers: Record<string, string>,
  options: RemoteFetchOptions,
): Promise<unknown> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(url, {
    method: 'GET',
    headers,
    redirect: 'error',
    signal: AbortSignal.timeout(options.timeoutMs),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json() as Promise<unknown>;
}

function httpsUrl(raw: string): URL {
  const url = new URL(raw);
  if (url.protocol !== 'https:') throw new Error('Remote scanner URL must be HTTPS');
  return url;
}

export async function fetchSnykIssues(
  input: RemoteFetchOptions & { token: string; orgId: string; apiBase?: string },
): Promise<unknown> {
  const base = httpsUrl(input.apiBase ?? 'https://api.snyk.io');
  const collected: unknown[] = [];
  let next: string | null =
    `${base.origin}/rest/orgs/${encodeURIComponent(input.orgId)}/issues?version=2024-10-15&limit=100`;
  for (let page = 0; page < 10 && next; page += 1) {
    const pageUrl = httpsUrl(next);
    if (pageUrl.origin !== base.origin) throw new Error('Snyk pagination left the API origin');
    const body = (await fetchJson(
      pageUrl.toString(),
      {
        accept: 'application/vnd.api+json',
        authorization: `token ${input.token}`,
      },
      input,
    )) as { data?: unknown[]; links?: { next?: string } };
    collected.push(...(Array.isArray(body.data) ? body.data : []));
    const candidate = body.links?.next;
    next = candidate && candidate.startsWith('https://') ? candidate : null;
  }
  return { data: collected };
}

export async function fetchVeracodeFindings(
  input: RemoteFetchOptions & { apiId: string; apiKeyHex: string; appGuid: string },
): Promise<unknown> {
  const url = `https://api.veracode.com/appsec/v2/applications/${encodeURIComponent(input.appGuid)}/findings`;
  const authorization = veracodeAuthorizationHeader({
    apiId: input.apiId,
    apiKeyHex: input.apiKeyHex,
    url,
    method: 'GET',
  });
  return fetchJson(url, { authorization }, input);
}

export async function fetchSemgrepFindings(
  input: RemoteFetchOptions & { token: string; deploymentId: string },
): Promise<unknown> {
  const url = `https://semgrep.dev/api/v1/deployments/${encodeURIComponent(input.deploymentId)}/findings?page_size=100`;
  return fetchJson(
    url,
    { authorization: `Bearer ${input.token}`, accept: 'application/json' },
    input,
  );
}

export interface GhasPage {
  codeScanning: unknown[];
  secretScanning: unknown[];
  dependabot: unknown[];
}

async function githubPages(
  input: RemoteFetchOptions & { token: string; url: string },
): Promise<unknown[]> {
  const collected: unknown[] = [];
  const first = httpsUrl(input.url);
  for (let page = 1; page <= 10; page += 1) {
    const pageUrl = new URL(first.toString());
    pageUrl.searchParams.set('per_page', '100');
    pageUrl.searchParams.set('page', String(page));
    const fetchImpl = input.fetchImpl ?? fetch;
    const response = await fetchImpl(pageUrl.toString(), {
      method: 'GET',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${input.token}`,
        'x-github-api-version': '2022-11-28',
      },
      redirect: 'error',
      signal: AbortSignal.timeout(input.timeoutMs),
    });
    if (response.status === 404) return collected;
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = (await response.json()) as unknown;
    if (!Array.isArray(body) || body.length === 0) break;
    collected.push(...body);
    if (body.length < 100) break;
  }
  return collected;
}

export async function fetchGhasAlerts(
  input: RemoteFetchOptions & {
    token: string;
    owner: string;
    repo: string;
    apiBase?: string;
  },
): Promise<GhasPage> {
  const base = httpsUrl(input.apiBase ?? 'https://api.github.com');
  const root = `${base.origin}/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}`;
  const [codeScanning, secretScanning, dependabot] = await Promise.all([
    githubPages({ ...input, url: `${root}/code-scanning/alerts?state=open` }),
    githubPages({ ...input, url: `${root}/secret-scanning/alerts?state=open` }),
    githubPages({ ...input, url: `${root}/dependabot/alerts?state=open` }),
  ]);
  return { codeScanning, secretScanning, dependabot };
}

export function safeRemoteMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return redactSecrets(message).slice(0, 180) || 'remote source failed';
}
