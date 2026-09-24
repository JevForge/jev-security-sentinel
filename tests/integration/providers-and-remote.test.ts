import { describe, expect, it, vi } from 'vitest';
import { createJevProvider } from '../../src/jev/factory.js';
import { interpretEvaluation } from '../../src/jev/normalize.js';
import { createVercelAiGatewayProvider } from '../../src/jev/vercel-ai-gateway.js';
import type { SentinelEvaluationState } from '../../src/jev/types.js';
import { veracodeAuthorizationHeader } from '../../src/integrations/veracode-hmac.js';
import { fetchGhasAlerts, fetchSemgrepFindings, fetchSnykIssues, fetchVeracodeFindings } from '../../src/collectors/remote.js';
import { redactSecrets } from '../../src/utils/sanitize.js';
import { loadFileConfig } from '../../src/collectors/config.js';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const state: SentinelEvaluationState = {
  environment: 'production',
  component: 'api',
  gateScope: 'changed',
  policyFloor: 'WARN',
  counts: { total: 1, in_scope: 1, blocking: 0, by_severity: { medium: 1 } },
  sample: [],
  note: 'untrusted',
};

describe('Jev providers', () => {
  it('rejects malformed choices and clamps confidence', () => {
    expect(interpretEvaluation({ answers: {} }).status).toBe('schema_rejected');
    expect(interpretEvaluation({
      answers: { gate_decision: { type: 'choice', choice: 'IGNORE' } },
    }).status).toBe('schema_rejected');
    const parsed = interpretEvaluation({
      answers: {
        gate_decision: { type: 'choice', choice: 'REVIEW', confidence: 4 },
        abstain: { type: 'boolean', probability: 0.8 },
      },
    });
    expect(parsed).toMatchObject({ status: 'evaluated', decision: 'REVIEW', confidence: 1, abstain: true });
  });

  it('does not fall back from the selected provider', async () => {
    const calls: string[] = [];
    const fetchImpl = vi.fn(async () => {
      calls.push('fetch');
      return new Response(JSON.stringify({
        answers: { gate_decision: { type: 'choice', choice: 'WARN', confidence: 0.9 } },
      }), { status: 200 });
    });
    const gateway = createJevProvider({
      provider: 'vercel-ai-gateway',
      timeoutMs: 1000,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(gateway.id).toBe('vercel-ai-gateway');
    const missing = await gateway.evaluateGate(state);
    expect(missing.status).toBe('unavailable');
    expect(calls).toEqual([]);

    const custom = createJevProvider({
      provider: 'custom-compatible',
      apiKey: 'secret',
      endpoint: 'http://insecure.example/evaluate',
      model: 'typesafe-ai/jev',
      timeoutMs: 1000,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect((await custom.evaluateGate(state)).status).toBe('unavailable');
    expect(calls).toEqual([]);
  });

  it('normalizes a gateway evaluation without calling generateText', async () => {
    const provider = createVercelAiGatewayProvider({
      apiKey: 'test-key',
      timeoutMs: 1000,
      evaluateImpl: async input => {
        expect(input.modelId).toBe('typesafe-ai/jev');
        expect(input.state.note).toBe('untrusted');
        return {
          answers: { gate_decision: { type: 'choice', choice: 'BLOCK' } },
          providerMetadata: { typesafe: { confidence: { gate_decision: 0.88 } } },
        };
      },
    });
    const result = await provider.evaluateGate(state);
    expect(result).toMatchObject({ status: 'evaluated', decision: 'BLOCK', confidence: 0.88 });
  });

  it('calls the native endpoint with the pinned model and refuses a non-https override', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      answers: { gate_decision: { type: 'choice', choice: 'PASS', confidence: 0.8 } },
    }), { status: 200 }));
    const provider = createJevProvider({
      provider: 'typesafe-native',
      apiKey: 'native-key',
      model: 'jev-catalog-1',
      endpoint: 'https://api.typesafe.ai/v1/evaluate',
      timeoutMs: 1000,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect((await provider.evaluateGate(state)).status).toBe('evaluated');
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://api.typesafe.ai/v1/evaluate');
    expect(String(init.body)).toContain('jev-catalog-1');
    expect(JSON.parse(String(init.body)).questions.gate_decision.criteria.BLOCK).toBeTruthy();
  });
});

describe('remote scanners', () => {
  it('signs Veracode requests and follows only same-origin Snyk pages', async () => {
    const nonce = Buffer.alloc(16, 1);
    const header = veracodeAuthorizationHeader({
      apiId: 'api-id',
      apiKeyHex: '00112233445566778899aabbccddeeff',
      url: 'https://api.veracode.com/appsec/v2/applications/app/findings',
      method: 'GET',
      nonce,
      timestamp: '1700000000000',
    });
    expect(header.startsWith('VERACODE-HMAC-SHA-256 id=api-id,ts=1700000000000,nonce=')).toBe(true);
    expect(header).not.toContain('00112233445566778899aabbccddeeff');
    const again = veracodeAuthorizationHeader({
      apiId: 'api-id',
      apiKeyHex: '00112233445566778899aabbccddeeff',
      url: 'https://api.veracode.com/appsec/v2/applications/app/findings',
      method: 'GET',
      nonce,
      timestamp: '1700000000000',
    });
    expect(again).toBe(header);

    const fetchImpl = vi.fn(async (url: string) => {
      if (String(url).includes('api.snyk.io') && !String(url).includes('starting_after')) {
        return new Response(JSON.stringify({
          data: [{ id: '1', attributes: { title: 'issue', effective_severity_level: 'low', type: 'package_vulnerability', key: 'K' } }],
          links: { next: 'https://api.snyk.io/rest/orgs/org/issues?version=2024-10-15&starting_after=1' },
        }), { status: 200 });
      }
      return new Response(JSON.stringify({ data: [], links: { next: 'http://evil.example/steal' } }), { status: 200 });
    });
    const snyk = await fetchSnykIssues({
      token: 'snyk-token',
      orgId: 'org',
      timeoutMs: 1000,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    }) as { data: unknown[] };
    expect(snyk.data).toHaveLength(1);
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    const veracodeFetch = vi.fn(async (_url: string, init?: RequestInit) => {
      expect(String((init?.headers as Record<string, string>).authorization)).toContain('VERACODE-HMAC-SHA-256');
      return new Response(JSON.stringify({ findings: [] }), { status: 200 });
    });
    await fetchVeracodeFindings({
      apiId: 'id',
      apiKeyHex: 'aa',
      appGuid: 'guid',
      timeoutMs: 1000,
      fetchImpl: veracodeFetch as unknown as typeof fetch,
    });

    const semgrepFetch = vi.fn(async () => new Response(JSON.stringify({ results: [] }), { status: 200 }));
    await fetchSemgrepFindings({
      token: 'semgrep-token',
      deploymentId: 'acme',
      timeoutMs: 1000,
      fetchImpl: semgrepFetch as unknown as typeof fetch,
    });
    expect(String((semgrepFetch.mock.calls[0] as unknown as [string])[0])).toContain('/deployments/acme/findings');
  });

  it('reads GitHub Advanced Security pages and stops on a short page', async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      const target = String(url);
      if (target.includes('code-scanning')) {
        return new Response(JSON.stringify([{ number: 1 }]), { status: 200 });
      }
      if (target.includes('secret-scanning')) return new Response('[]', { status: 200 });
      if (target.includes('dependabot')) return new Response(JSON.stringify([]), { status: 404 });
      throw new Error(`unexpected ${target}`);
    });
    const page = await fetchGhasAlerts({
      token: 'gh-token',
      owner: 'JevForge',
      repo: 'demo',
      timeoutMs: 1000,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(page.codeScanning).toHaveLength(1);
    expect(page.secretScanning).toEqual([]);
    expect(page.dependabot).toEqual([]);
    expect(redactSecrets('Bearer ghp_abcdefghijklmnopqrstuvwxyz123456')).toContain('[REDACTED]');
  });

  it('loads .jev/config.yml', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sentinel-cfg-'));
    mkdirSync(join(dir, '.jev'));
    writeFileSync(join(dir, '.jev', 'config.yml'), 'jev_provider: typesafe-native\nmin_confidence: 0.8\nblock_secrets: true\n');
    expect(loadFileConfig(dir).jev_provider).toBe('typesafe-native');
    expect(loadFileConfig(dir).min_confidence).toBe(0.8);
  });
});
