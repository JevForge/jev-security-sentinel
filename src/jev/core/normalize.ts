import { GATE_DECISIONS, type GateDecision } from '../../schemas/enums.js';
import type { EvaluationBody, JevCallResult } from './types.js';

function clampConfidence(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

export function interpretEvaluation(body: EvaluationBody): JevCallResult {
  const selected = body.answers?.gate_decision;
  if (!selected || selected.type !== 'choice' || typeof selected.choice !== 'string') {
    return { status: 'schema_rejected', message: 'SCHEMA_REJECTED: missing gate_decision choice' };
  }
  if (!(GATE_DECISIONS as readonly string[]).includes(selected.choice)) {
    return {
      status: 'schema_rejected',
      message: `SCHEMA_REJECTED: gate_decision ${selected.choice} is not allowed`,
    };
  }
  const typesafe = body.providerMetadata?.typesafe?.confidence?.gate_decision;
  const confidence = clampConfidence(
    typesafe ?? body.confidence?.gate_decision ?? selected.confidence ?? selected.probability ?? 0,
  );
  const abstain = body.answers?.abstain;
  const abstainProbability = abstain?.type === 'boolean' ? abstain.probability : undefined;
  return {
    status: 'evaluated',
    decision: selected.choice as GateDecision,
    confidence,
    explanation: `Jev proposed ${selected.choice}`,
    abstain: (abstainProbability ?? 0) >= 0.55,
  };
}

export function unavailable(message: string): JevCallResult {
  return { status: 'unavailable', message: message.slice(0, 500) };
}
