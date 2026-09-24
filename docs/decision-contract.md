# Decision contract

The public decision is a strict object. Unknown fields are rejected. The deterministic policy produces this object after Jev responds; Jev does not get to omit findings or add executable fields.

## Valid

```json
{
  "decision": "BLOCK",
  "confidence": 0.91,
  "reason_codes": ["CRITICAL_IN_SCOPE", "PRODUCTION_ENVIRONMENT", "POLICY_FLOOR_BLOCK", "JEV_AGREED", "FINDINGS_PRESERVED"],
  "findings": [
    {
      "id": "sarif:abc123",
      "fingerprint": "abc123abc123abcd",
      "source": "sarif",
      "category": "sast",
      "severity": "critical",
      "title": "SQL injection",
      "rule_id": "java.sql-injection",
      "path": "src/db.ts",
      "start_line": 20,
      "component": "api",
      "environment": "production",
      "cve": null,
      "exploitability": "unknown",
      "in_change": true,
      "allowlisted": false,
      "excluded": false,
      "baseline_matched": false,
      "gate_effect": "blocking",
      "message": "user input reaches a query"
    }
  ],
  "risk_summary": {
    "total": 1,
    "in_scope": 1,
    "blocking": 1,
    "warning": 0,
    "review": 0,
    "allowlisted": 0,
    "out_of_scope": 0,
    "baseline": 0,
    "by_severity": { "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0 },
    "by_category": { "sast": 1, "sca": 0, "iac": 0, "secrets": 0, "container": 0, "license": 0, "other": 0 },
    "highest_severity": "critical",
    "source_errors": [],
    "truncated": false
  },
  "explanation": "Critical finding remains in scope.",
  "provisional": false,
  "jev_status": "evaluated",
  "jev_proposed": "BLOCK",
  "policy_floor": "BLOCK",
  "policy_id": "default-gate"
}
```

A second valid shape is a provisional review when Jev is down and there is nothing to block:

```json
{
  "decision": "REVIEW",
  "confidence": 0,
  "reason_codes": ["NO_FINDINGS", "JEV_UNAVAILABLE", "REVIEW_REQUIRED"],
  "findings": [],
  "jev_status": "unavailable",
  "jev_proposed": null,
  "policy_floor": "PASS",
  "provisional": true
}
```

`jev_proposed: null` is required here. Inventing a PASS from a missing model response is invalid.

## Invalid

| Payload | Why it is rejected |
| --- | --- |
| `{ "decision": "SUPPRESS" }` | Decision is not PASS, WARN, BLOCK, or REVIEW. |
| `{ "confidence": 1.4 }` | Confidence must be between 0 and 1. |
| `{ "reason_codes": [] }` | At least one stable reason code is required. |
| `{ "decision": "PASS", "findings": [{ "gate_effect": "blocking" }] }` | A visible blocking finding cannot be paired with PASS. |
| `{ "shell_command": "rm -rf /" }` | Unknown fields are rejected. Explanation text is never executed. |
| `{ "jev_status": "unavailable", "jev_proposed": "PASS", "provisional": false }` | An unavailable provider must not invent a proposal or look final. |
| `{ "decision": "BLOCK", "findings": [], "source_errors": [] }` | BLOCK needs preserved findings or a recorded source failure. |
| A Jev choice of `IGNORE` | The provider records `schema_rejected` and the policy floor is used instead. |

Allowlisted findings stay in `findings` with `gate_effect: "allowlisted"`. They do not raise the floor, and they are not removed from outputs, comments, or annotations lists (annotations skip them because they are not in scope).
