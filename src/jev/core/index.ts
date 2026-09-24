/**
 * Stable Jev client boundary for JEV Security Sentinel.
 *
 * Action code should import from `src/jev/core` (this module). Provider
 * adapters live beside this folder and are implementation details.
 * A future `@jevforge/core` package can lift these exports without changing
 * the Action's gate policy.
 */
export type {
  EvaluationAnswer,
  EvaluationBody,
  JevCallResult,
  JevProvider,
  JevProviderOptions,
  SentinelEvaluationState,
} from './types.js';
export { createJevProvider, type CreateJevProviderInput } from './factory.js';
export { interpretEvaluation, unavailable } from './normalize.js';
export { buildGateQuestions, summarizeState } from './questions.js';
