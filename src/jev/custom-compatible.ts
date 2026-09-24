import type { JevProvider, JevProviderOptions, SentinelEvaluationState } from './types.js';
import { buildGateQuestions, summarizeState } from './questions.js';
import { interpretEvaluation, unavailable } from './normalize.js';
import type { EvaluationBody } from './types.js';

export function createCustomCompatibleProvider(options: JevProviderOptions): JevProvider {
  const fetchImpl = options.fetchImpl ?? fetch;
  return {
    id: 'custom-compatible',
    async evaluateGate(state: SentinelEvaluationState) {
      if (!options.apiKey) return unavailable('JEV_CUSTOM_API_KEY is required for custom-compatible');
      if (!options.endpoint) return unavailable('jev_endpoint is required for custom-compatible');
      if (!options.endpoint.startsWith('https://')) {
        return unavailable('jev_endpoint must be HTTPS for custom-compatible');
      }
      if (!options.model) return unavailable('jev_model is required for custom-compatible');
      try {
        const response = await fetchImpl(options.endpoint, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${options.apiKey}`,
          },
          body: JSON.stringify({
            model: options.model,
            state: summarizeState(state),
            questions: buildGateQuestions(),
          }),
          redirect: 'error',
          signal: AbortSignal.timeout(options.timeoutMs),
        });
        if (!response.ok) return unavailable(`custom-compatible HTTP ${response.status}`);
        return interpretEvaluation((await response.json()) as EvaluationBody);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return unavailable(`custom-compatible error: ${message}`);
      }
    },
  };
}
