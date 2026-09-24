import type { EnvironmentName, GateDecision, GateScope, JevProviderId } from '../schemas/enums.js';
import type { JevFindingSample } from '../decision/prioritize.js';

export interface SentinelEvaluationState {
  environment: EnvironmentName;
  component: string;
  gateScope: GateScope;
  policyFloor: GateDecision;
  counts: {
    total: number;
    in_scope: number;
    blocking: number;
    by_severity: Record<string, number>;
  };
  sample: JevFindingSample[];
  note: string;
}

export type JevCallResult =
  | {
      status: 'evaluated';
      decision: GateDecision;
      confidence: number;
      explanation: string;
      abstain: boolean;
    }
  | { status: 'unavailable'; message: string }
  | { status: 'schema_rejected'; message: string };

export interface JevProvider {
  readonly id: JevProviderId;
  evaluateGate(state: SentinelEvaluationState): Promise<JevCallResult>;
}

export interface JevProviderOptions {
  apiKey?: string;
  endpoint?: string;
  model?: string;
  timeoutMs: number;
  fetchImpl?: typeof fetch;
}

export interface EvaluationAnswer {
  type?: string;
  choice?: string;
  probability?: number;
  confidence?: number;
}

export interface EvaluationBody {
  answers?: Record<string, EvaluationAnswer>;
  confidence?: Record<string, number>;
  providerMetadata?: { typesafe?: { confidence?: Record<string, number> } };
}
