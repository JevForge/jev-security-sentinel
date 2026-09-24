import type { JevProvider, JevProviderOptions, SentinelEvaluationState } from './types.js';
import { buildGateQuestions, summarizeState } from './questions.js';
import { interpretEvaluation, unavailable } from './normalize.js';
import type { EvaluationBody } from './types.js';

export function createTypesafeNativeProvider(options: JevProviderOptions): JevProvider {
  const fetchImpl = options.fetchImpl ?? fetch;
  const endpoint = options.endpoint ?? 'https://api.typesafe.ai/v1/evaluate';
  return {
    id: 'typesafe-native',
    async evaluateGate(state: SentinelEvaluationState) {
      if (!options.apiKey) return unavailable('TYPESAFE_API_KEY is required for typesafe-native');
      if (!options.model) {
        return unavailable('jev_model is required for typesafe-native (pin a catalog model id)');
      }
      if (!endpoint.startsWith('https://')) {
        return unavailable('typesafe-native endpoint must be HTTPS');
      }
      try {
        const response = await fetchImpl(endpoint, {
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
        if (!response.ok) return unavailable(`typesafe-native HTTP ${response.status}`);
        return interpretEvaluation((await response.json()) as EvaluationBody);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return unavailable(`typesafe-native error: ${message}`);
      }
    },
  };
}
