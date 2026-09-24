import * as core from '@actions/core';
import * as github from '@actions/github';
import { loadFileConfig, policyFromConfig, coalesceEnvironment, coalescePolicy, coalesceProvider, coalesceReviewMode, coalesceScope, coalesceSourceErrors, pickEnum } from './collectors/config.js';
import { loadFindings } from './collectors/load.js';
import { loadBaselineFingerprints } from './collectors/baseline.js';
import { listChangedPaths } from './collectors/github-context.js';
import { fetchGhasAlerts, fetchSemgrepFindings, fetchSnykIssues, fetchVeracodeFindings, safeRemoteMessage } from './collectors/remote.js';
import { createJevProvider } from './jev/factory.js';
import { runSentinel } from './run.js';
import { writeDecisionOutputs, formatActionMessage } from './github/outputs.js';
import type { SourceError } from './schemas/sentinel.js';
import { GATE_MODES } from './schemas/enums.js';
function optionalBoolean(name: string, fallback: boolean): boolean {
  const raw = core.getInput(name);
  if (!raw) return fallback;
  return raw.toLowerCase() === 'true';
}

function resolveApiKey(provider: string): string | undefined {
  if (provider === 'vercel-ai-gateway') return process.env.AI_GATEWAY_API_KEY || undefined;
  if (provider === 'typesafe-native') return process.env.TYPESAFE_API_KEY || undefined;
  return process.env.JEV_CUSTOM_API_KEY || undefined;
}

async function main(): Promise<void> {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const config = loadFileConfig(workspace);
  const jevProvider = coalesceProvider(core.getInput('jev_provider') || undefined, config);
  const onPullRequest = Boolean(github.context.payload.pull_request);
  const environment = coalesceEnvironment(core.getInput('environment') || undefined, config);
  const gateScope = coalesceScope(
    core.getInput('gate_scope') || undefined,
    config,
    onPullRequest ? 'changed' : 'all',
  );
  const gateMode = pickEnum(
    core.getInput('gate_mode') || undefined,
    config.gate_mode ?? 'all',
    GATE_MODES,
    'gate_mode',
  );
  const lowConfidence = coalescePolicy(core.getInput('low_confidence_policy') || undefined, config);
  const reviewMode = coalesceReviewMode(core.getInput('review_mode') || undefined, config);
  const sourceErrorPolicy = coalesceSourceErrors(core.getInput('source_error_policy') || undefined, config);
  const policy = policyFromConfig(config);
  const timeoutMs = Number(core.getInput('timeout_ms') || 45_000);
  const dryRun = optionalBoolean('dry_run', false);
  const comment = optionalBoolean('comment_on_github', config.comment_on_github ?? false);
  const annotate = optionalBoolean('annotate', config.annotate ?? true);
  const token = core.getInput('github_token') || process.env.GITHUB_TOKEN || '';

  const remoteErrors: SourceError[] = [];
  const remote: {
    semgrep?: unknown;
    snyk?: unknown;
    veracode?: unknown;
    codeScanning?: unknown;
    secretScanning?: unknown;
    dependabot?: unknown;
  } = {};

  if (optionalBoolean('fetch_ghas', false)) {
    if (!token) remoteErrors.push({ source: 'ghas', message: 'github_token is required to fetch GitHub Advanced Security alerts' });
    else {
      try {
        const alerts = await fetchGhasAlerts({
          token,
          owner: github.context.repo.owner,
          repo: github.context.repo.repo,
          timeoutMs,
        });
        remote.codeScanning = alerts.codeScanning;
        remote.secretScanning = alerts.secretScanning;
        remote.dependabot = alerts.dependabot;
      } catch (error) {
        remoteErrors.push({ source: 'ghas', message: safeRemoteMessage(error) });
      }
    }
  }

  if (optionalBoolean('fetch_snyk', false)) {
    const snykToken = process.env.SNYK_TOKEN;
    const orgId = core.getInput('snyk_org_id');
    if (!snykToken || !orgId) {
      remoteErrors.push({ source: 'snyk', message: 'SNYK_TOKEN and snyk_org_id are required' });
    } else {
      try {
        remote.snyk = await fetchSnykIssues({
          token: snykToken,
          orgId,
          apiBase: core.getInput('snyk_api_base') || undefined,
          timeoutMs,
        });
      } catch (error) {
        remoteErrors.push({ source: 'snyk', message: safeRemoteMessage(error) });
      }
    }
  }

  if (optionalBoolean('fetch_veracode', false)) {
    const apiId = process.env.VERACODE_API_ID;
    const apiKey = process.env.VERACODE_API_KEY;
    const appGuid = core.getInput('veracode_app_guid');
    if (!apiId || !apiKey || !appGuid) {
      remoteErrors.push({ source: 'veracode', message: 'VERACODE_API_ID, VERACODE_API_KEY, and veracode_app_guid are required' });
    } else {
      try {
        remote.veracode = await fetchVeracodeFindings({ apiId, apiKeyHex: apiKey, appGuid, timeoutMs });
      } catch (error) {
        remoteErrors.push({ source: 'veracode', message: safeRemoteMessage(error) });
      }
    }
  }

  if (optionalBoolean('fetch_semgrep', false)) {
    const semgrepToken = process.env.SEMGREP_APP_TOKEN;
    const deploymentId = core.getInput('semgrep_deployment_id');
    if (!semgrepToken || !deploymentId) {
      remoteErrors.push({ source: 'semgrep', message: 'SEMGREP_APP_TOKEN and semgrep_deployment_id are required' });
    } else {
      try {
        remote.semgrep = await fetchSemgrepFindings({ token: semgrepToken, deploymentId, timeoutMs });
      } catch (error) {
        remoteErrors.push({ source: 'semgrep', message: safeRemoteMessage(error) });
      }
    }
  }

  let changedPaths: string[] | null = null;
  let changedUnknown = false;
  const changedInput = core.getInput('changed_paths');
  if (changedInput.trim()) {
    const parsed = JSON.parse(changedInput) as unknown;
    if (!Array.isArray(parsed) || parsed.some(item => typeof item !== 'string')) {
      throw new Error('changed_paths must be a JSON array of strings');
    }
    changedPaths = parsed;
  } else if (gateScope === 'changed' && onPullRequest && token) {
    try {
      const pullNumber = Number(github.context.payload.pull_request?.number);
      const octokit = github.getOctokit(token);
      changedPaths = await listChangedPaths(
        {
          async listPullFiles(owner, repo, pull) {
            const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
              owner,
              repo,
              pull_number: pull,
              per_page: 100,
            });
            return files.map(file => file.filename);
          },
        },
        github.context.repo.owner,
        github.context.repo.repo,
        pullNumber,
      );
    } catch (error) {
      changedUnknown = true;
      changedPaths = null;
      core.warning(
        formatActionMessage(`Could not list pull request files: ${safeRemoteMessage(error)}`),
      );
    }
  } else if (gateScope === 'changed') {
    changedUnknown = true;
    changedPaths = null;
  }

  const loaded = loadFindings({
    workspace,
    normalizedJson: core.getInput('findings') || undefined,
    normalizedPath: core.getInput('findings_path') || undefined,
    sarifPath: core.getInput('sarif_path') || undefined,
    semgrepPath: core.getInput('semgrep_path') || undefined,
    trivyPath: core.getInput('trivy_path') || undefined,
    snykPath: core.getInput('snyk_path') || undefined,
    veracodePath: core.getInput('veracode_path') || undefined,
    maxFindings: Number(core.getInput('max_findings') || config.max_findings || 2000),
    remote,
  });
  if (loaded.loadedPaths.length > 0) {
    core.info(
      formatActionMessage(
        `Loaded ${loaded.loadedPaths.length} report file(s): ${loaded.loadedPaths.slice(0, 12).join(', ')}${loaded.loadedPaths.length > 12 ? ', …' : ''}`,
      ),
    );
  }

  let baselineFingerprints = new Set<string>();
  const baselinePath = core.getInput('baseline_path') || undefined;
  if (gateMode === 'new_only') {
    if (!baselinePath) {
      remoteErrors.push({
        source: 'baseline',
        message: 'gate_mode=new_only requires baseline_path',
      });
    } else {
      const baseline = loadBaselineFingerprints(workspace, baselinePath);
      baselineFingerprints = baseline.fingerprints;
      if (baseline.error) {
        remoteErrors.push({ source: 'baseline', message: baseline.error });
      }
    }
  }

  core.info(formatActionMessage(`Jev provider: ${jevProvider}`));
  core.info(
    formatActionMessage(
      'Data sent to Jev: environment, component, gate scope, severity counts, and a redacted sample of finding ids, rules, paths, and titles. Secrets, tokens, and raw secret matches are not sent.',
    ),
  );

  const provider = createJevProvider({
    provider: jevProvider,
    apiKey: resolveApiKey(jevProvider),
    endpoint: core.getInput('jev_endpoint') || config.jev_endpoint,
    model: core.getInput('jev_model') || config.jev_model,
    timeoutMs,
  });

  const pullNumber = github.context.payload.pull_request?.number ?? github.context.payload.issue?.number;
  const octokit = token ? github.getOctokit(token) : null;
  const commentClient =
    octokit && pullNumber
      ? {
          async createComment(body: string) {
            await octokit.rest.issues.createComment({
              owner: github.context.repo.owner,
              repo: github.context.repo.repo,
              issue_number: Number(pullNumber),
              body,
            });
          },
        }
      : null;

  const result = await runSentinel({
    rawFindings: loaded.findings,
    sourceErrors: [...loaded.errors, ...remoteErrors],
    truncated: loaded.truncated,
    policy,
    changedPaths,
    baselineFingerprints,
    provider,
    commentClient,
    options: {
      environment,
      component: core.getInput('component') || config.component || '',
      gate_scope: gateScope,
      gate_mode: gateMode,
      min_confidence: Number(core.getInput('min_confidence') || config.min_confidence || 0.75),
      low_confidence_policy: lowConfidence,
      source_error_policy: sourceErrorPolicy,
      review_mode: reviewMode,
      jev_provider: jevProvider,
      jev_endpoint: core.getInput('jev_endpoint') || config.jev_endpoint,
      jev_model: core.getInput('jev_model') || config.jev_model,
      timeout_ms: timeoutMs,
      dry_run: dryRun,
      comment_on_github: comment,
      annotate: annotate,
      max_findings: Number(core.getInput('max_findings') || config.max_findings || 2000),
      max_findings_to_jev: Number(core.getInput('max_findings_to_jev') || config.max_findings_to_jev || 40),
      changed_paths_unknown: changedUnknown,
    },
  });

  const writer = {
    setOutput: (name: string, value: string) => core.setOutput(name, value),
    setFailed: (message: string) => core.setFailed(message),
    warning: (message: string, properties?: { file?: string; startLine?: number; title?: string }) =>
      core.warning(message, properties),
    info: (message: string) => core.info(message),
    error: (message: string, properties?: { file?: string; startLine?: number; title?: string }) =>
      core.error(message, properties),
    notice: (message: string, properties?: { file?: string; startLine?: number; title?: string }) =>
      core.notice(message, properties),
  };

  writeDecisionOutputs(writer, result.decision, result.outcome.action_status, workspace);
  if (!dryRun) {
    for (const annotation of result.effects.annotations) {
      const payload = {
        file: annotation.path,
        startLine: annotation.startLine,
        title: annotation.title,
      };
      if (annotation.level === 'error') writer.error(annotation.message, payload);
      else if (annotation.level === 'warning') writer.warning(annotation.message, payload);
      else writer.notice(annotation.message, payload);
    }
  }
  core.info(formatActionMessage(`Comment: ${result.commentStatus}`));
  core.info(formatActionMessage(`Effects: ${result.effects.effects.join(',')}`));
}

main().catch(error => {
  const message = error instanceof Error ? error.message : String(error);
  core.setFailed(formatActionMessage(message));
});
