import { describe, expect, it, vi } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { matchGlob } from '../../src/utils/glob.js';
import { normalizeRepoPath, redactSecrets } from '../../src/utils/sanitize.js';
import {
  coalesceEnvironment,
  coalescePolicy,
  coalesceProvider,
  coalesceReviewMode,
  coalesceScope,
  coalesceSourceErrors,
  loadFileConfig,
  policyFromConfig,
} from '../../src/collectors/config.js';
import { loadFindings } from '../../src/collectors/load.js';
import { listChangedPaths } from '../../src/collectors/github-context.js';
import { applyGate } from '../../src/decision/policy.js';
import { annotateFindings } from '../../src/decision/annotate.js';
import { DEFAULT_POLICY, resolvePolicy } from '../../src/schemas/sentinel.js';
import { createCustomCompatibleProvider } from '../../src/jev/custom-compatible.js';
import { createTypesafeNativeProvider } from '../../src/jev/typesafe-native.js';
import { createVercelAiGatewayProvider } from '../../src/jev/vercel-ai-gateway.js';
import { veracodeAuthorizationHeader } from '../../src/integrations/veracode-hmac.js';
import { maybePostComment } from '../../src/executors/comment.js';
import { writeDecisionOutputs } from '../../src/github/outputs.js';
import type { RawFinding } from '../../src/collectors/common.js';
import type { SentinelEvaluationState } from '../../src/jev/types.js';
import type { SentinelDecision } from '../../src/schemas/sentinel.js';

const state: SentinelEvaluationState = {
  environment: 'production',
  component: 'api',
  gateScope: 'all',
  policyFloor: 'PASS',
  counts: { total: 0, in_scope: 0, blocking: 0, by_severity: {} },
  sample: [],
  note: 'note',
};

const row = (overrides: Partial<RawFinding> = {}): RawFinding => ({
  source: 'normalized',
  category: 'sast',
  severity: 'medium',
  title: 'issue',
  rule_id: 'R',
  path: 'src/a.ts',
  start_line: 2,
  cve: null,
  exploitability: 'unknown',
  message: 'm',
  component: '',
  scanner_suppressed: false,
  ...overrides,
});

describe('edges', () => {
  it('matches globs and rejects unsafe paths', () => {
    expect(matchGlob('src/**/*.ts', 'src/a/b.ts')).toBe(true);
    expect(matchGlob('src/*.ts', 'src/a/b.ts')).toBe(false);
    expect(normalizeRepoPath('../etc/passwd')).toBeNull();
    expect(normalizeRepoPath('/abs/file.ts')).toBeNull();
    expect(normalizeRepoPath('file://src/app.ts')).toBe('src/app.ts');
    expect(redactSecrets('VERACODE-HMAC-SHA-256 id=1,sig=abc')).toContain('[REDACTED]');
  });

  it('coalesces config and rejects unknown providers', () => {
    const config = {
      jev_provider: 'typesafe-native' as const,
      environment: 'development' as const,
      low_confidence_policy: 'warn' as const,
      review_mode: 'continue' as const,
      source_error_policy: 'warn' as const,
      gate_scope: 'all' as const,
    };
    expect(coalesceProvider(undefined, config)).toBe('typesafe-native');
    expect(coalesceEnvironment(undefined, config)).toBe('development');
    expect(coalescePolicy('fail', config)).toBe('fail');
    expect(coalesceReviewMode(undefined, config)).toBe('continue');
    expect(coalesceSourceErrors(undefined, config)).toBe('warn');
    expect(coalesceScope(undefined, {}, 'changed')).toBe('changed');
    expect(() => coalesceProvider('openai', {})).toThrow(/jev_provider/);
    expect(loadFileConfig(mkdtempSync(join(tmpdir(), 'empty-cfg-')))).toEqual({});
    const policy = policyFromConfig({
      policy_id: 'team',
      block_secrets: false,
      allowlist: { rule_ids: ['R'] },
      exclude_paths: ['vendor/**'],
    });
    expect(policy.id).toBe('team');
    expect(policy.block_secrets).toBe(false);
    expect(policy.allowlist.rule_ids).toEqual(['R']);
  });

  it('records missing files, bad JSON, and truncation', () => {
    const dir = mkdtempSync(join(tmpdir(), 'load-'));
    writeFileSync(join(dir, 'bad.json'), '{');
    const broken = loadFindings({
      workspace: dir,
      normalizedJson: '{',
      normalizedPath: 'missing.json',
      sarifPath: 'bad.json',
      maxFindings: 1,
    });
    expect(broken.errors.length).toBeGreaterThan(0);

    const many = loadFindings({
      workspace: dir,
      normalizedJson: JSON.stringify([
        { title: 'a', severity: 'info', rule_id: 'A', category: 'other' },
        { title: 'b', severity: 'info', rule_id: 'B', category: 'other' },
      ]),
      maxFindings: 1,
    });
    expect(many.truncated).toBe(true);
    expect(many.findings).toHaveLength(1);

    const remoteDir = mkdtempSync(join(tmpdir(), 'load-remote-'));
    const remote = loadFindings({
      workspace: remoteDir,
      maxFindings: 5,
      remote: {
        semgrep: {},
        snyk: {},
        veracode: {},
        codeScanning: {},
        secretScanning: {},
        dependabot: {},
      },
    });
    expect(remote.errors.length).toBe(6);
  });

  it('covers provider failure branches and a successful custom endpoint', async () => {
    const insecure = createTypesafeNativeProvider({
      apiKey: 'k',
      model: 'jev',
      endpoint: 'http://bad',
      timeoutMs: 1000,
    });
    const insecureResult = await insecure.evaluateGate(state);
    expect(insecureResult.status === 'unavailable' && insecureResult.message).toMatch(/HTTPS/);
    const noModel = createTypesafeNativeProvider({ apiKey: 'k', timeoutMs: 1000 });
    const missingModel = await noModel.evaluateGate(state);
    expect(missingModel.status === 'unavailable' && missingModel.message).toMatch(/jev_model/);

    const httpFail = createTypesafeNativeProvider({
      apiKey: 'k',
      model: 'jev',
      timeoutMs: 1000,
      fetchImpl: vi.fn(async () => new Response('no', { status: 503 })) as unknown as typeof fetch,
    });
    const httpResult = await httpFail.evaluateGate(state);
    expect(httpResult.status === 'unavailable' && httpResult.message).toContain('HTTP 503');

    const custom = createCustomCompatibleProvider({
      apiKey: 'k',
      endpoint: 'https://jev.example/evaluate',
      model: 'typesafe-ai/jev',
      timeoutMs: 1000,
      fetchImpl: vi.fn(async () => new Response(JSON.stringify({
        answers: { gate_decision: { type: 'choice', choice: 'WARN', confidence: 0.81 } },
      }), { status: 200 })) as unknown as typeof fetch,
    });
    expect(await custom.evaluateGate(state)).toMatchObject({ status: 'evaluated', decision: 'WARN' });

    const missingCustom = createCustomCompatibleProvider({ timeoutMs: 1000 });
    expect((await missingCustom.evaluateGate(state)).status).toBe('unavailable');

    const gateway = createVercelAiGatewayProvider({
      apiKey: 'k',
      timeoutMs: 1000,
      evaluateImpl: async () => {
        throw new Error('timeout');
      },
    });
    const gatewayResult = await gateway.evaluateGate(state);
    expect(gatewayResult.status === 'unavailable' && gatewayResult.message).toContain('timeout');
    expect(() => veracodeAuthorizationHeader({
      apiId: 'id',
      apiKeyHex: '',
      url: 'https://api.veracode.com/x',
      method: 'GET',
    })).toThrow(/hex/);
  });

  it('escalates known exploited findings and keeps excluded paths visible', () => {
    const policy = resolvePolicy({ exclude_paths: ['skip/**'] });
    const findings = annotateFindings({
      raw: [
        row({ severity: 'medium', exploitability: 'known_exploited', cve: 'CVE-2024-0001', path: 'src/a.ts' }),
        row({ path: 'skip/vendor.ts', rule_id: 'SKIP', severity: 'critical' }),
      ],
      policy,
      environment: 'development',
      component: 'web',
      gateScope: 'all',
      changedPaths: ['src/a.ts'],
    });
    expect(findings[0]?.gate_effect).toBe('blocking');
    expect(findings[1]?.excluded).toBe(true);
    const outcome = applyGate({
      findings,
      policy,
      jev: { status: 'evaluated', decision: 'PASS', confidence: 0.99, explanation: 'no', abstain: true },
      minConfidence: 0.75,
      lowConfidencePolicy: 'warn',
      sourceErrorPolicy: 'warn',
      reviewMode: 'continue',
      sourceErrors: [{ source: 'trivy', message: 'HTTP 500' }],
      truncated: false,
      changedPathsUnknown: true,
    });
    expect(outcome.decision.decision).toBe('BLOCK');
    expect(outcome.decision.reason_codes).toContain('JEV_ABSTAIN');
    expect(outcome.decision.reason_codes).toContain('KNOWN_EXPLOITED');
    expect(outcome.action_status).toBe('fail');
  });

  it('warns when Jev is unavailable under the warn policy', () => {
    const findings = annotateFindings({
      raw: [],
      policy: DEFAULT_POLICY,
      environment: 'test',
      component: '',
      gateScope: 'all',
      changedPaths: [],
    });
    const outcome = applyGate({
      findings,
      policy: DEFAULT_POLICY,
      jev: { status: 'unavailable', message: 'down' },
      minConfidence: 0.75,
      lowConfidencePolicy: 'warn',
      sourceErrorPolicy: 'warn',
      reviewMode: 'continue',
      sourceErrors: [],
      truncated: false,
      changedPathsUnknown: false,
    });
    expect(outcome.decision.decision).toBe('WARN');
    expect(outcome.action_status).toBe('warn');
  });

  it('skips comments in dry-run and fails the writer on a blocking status', async () => {
    const decision = applyGate({
      findings: annotateFindings({
        raw: [row({ severity: 'critical' })],
        policy: DEFAULT_POLICY,
        environment: 'staging',
        component: 'api',
        gateScope: 'all',
        changedPaths: null,
      }),
      policy: DEFAULT_POLICY,
      jev: { status: 'evaluated', decision: 'BLOCK', confidence: 0.9, explanation: 'block', abstain: false },
      minConfidence: 0.75,
      lowConfidencePolicy: 'fail',
      sourceErrorPolicy: 'fail',
      reviewMode: 'fail',
      sourceErrors: [],
      truncated: false,
      changedPathsUnknown: false,
    }).decision;
    expect(await maybePostComment(true, true, decision, { async createComment() {} })).toBe('dry-run');
    expect(await maybePostComment(false, false, decision, null)).toBe('skipped');
    const failed: string[] = [];
    writeDecisionOutputs({
      setOutput: () => undefined,
      setFailed: message => failed.push(message),
      warning: () => undefined,
      info: () => undefined,
      error: () => undefined,
      notice: () => undefined,
    }, decision, 'fail');
    expect(failed[0]).toContain('BLOCK');
    const paths = await listChangedPaths({
      async listPullFiles() {
        return ['src/a.ts'];
      },
    }, 'JevForge', 'demo', 4);
    expect(paths).toEqual(['src/a.ts']);
    expect(decision.reason_codes.length).toBeGreaterThan(0);
    void (decision satisfies SentinelDecision);
  });
});
