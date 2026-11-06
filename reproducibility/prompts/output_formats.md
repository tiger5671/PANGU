# Prompt output formats

These formats describe the four parameterized templates in this directory. They document the intended fields and interpretation; they are not a claim that the application's current internal API has been audited against them.

Each response is one JSON object. The caller checks required fields, types, allowed labels, code references, and consistency between fields. API failures and invalid or incomplete structured responses permit at most three total attempts per request. Exhausted requests remain unsuccessful or unresolved.

## Route classification

| Field | Type | Meaning |
| --- | --- | --- |
| `class` | string | `URL_PATH`, `ACTION_MAP`, or `RESOURCE_MAP`. |
| `is_executable_route` | boolean | Whether the record has supported dispatch and handler evidence for an executable interface. |
| `handler_ref` | string or null | Supported handler reference, if identified. |
| `evidence_refs` | array of strings | Registration, comparison, or cross-reference locations. |
| `explanation` | string | Reason for the classification. |
| `status` | string | `RESOLVED` or `UNRESOLVED`. The status is separate from the route class. |

Only evidence-supported `URL_PATH` and `ACTION_MAP` records may enter the executable-route set. `RESOURCE_MAP` records are filtered out. Unresolved records are not promoted to executable routes.

Illustrative example; all `example:` references are placeholders:

```json
{
  "class": "RESOURCE_MAP",
  "is_executable_route": false,
  "handler_ref": null,
  "evidence_refs": ["example:mime_table_entry"],
  "explanation": "The string is used as a MIME value in a resource table.",
  "status": "RESOLVED"
}
```

## Security-check classification

| Field | Type | Meaning |
| --- | --- | --- |
| `check_label` | string | `AUTHENTICATION`, `AUTHORIZATION`, `NON_SECURITY`, or `UNRESOLVED`. |
| `checkpoint_ref` | string | Candidate condition/block reference. |
| `evidence_refs` | array of strings | Predicates, called routines, or successors used for classification. |
| `explanation` | string | Why the condition has the selected purpose. |
| `source_kind` | string | `PATH_DOMINATING` or `ASYMMETRIC_GUARD`, matching the input. |

Evidence-supported authentication and authorization labels enter the corresponding checkpoint sets. `NON_SECURITY` is filtered out. `UNRESOLVED` requires further inspection. This classification identifies a check's purpose; the agents examine enforcement behavior later.

Illustrative example:

```json
{
  "check_label": "NON_SECURITY",
  "checkpoint_ref": "example:read_error_condition",
  "evidence_refs": ["example:file_read_call", "example:error_return"],
  "explanation": "The condition handles a file-read error.",
  "source_kind": "ASYMMETRIC_GUARD"
}
```

## Detective Agent

| Field | Type | Meaning |
| --- | --- | --- |
| `route_id` | string | Recovered route reference. |
| `handler_ref` | string | Backend handler reference. |
| `decision` | string | `CANDIDATE`, `NO_FINDING`, or `INSUFFICIENT_EVIDENCE`. |
| `hypothesized_weakness` | string or null | Proposed failure mechanism. |
| `sensitive_operation_ref` | string or null | Relevant sensitive call or state change. |
| `auth_check_refs` | array of strings | Authentication/authorization conditions examined. |
| `evidence_refs` | array of strings | Retrieved code, CFG, and cross-reference locations. |
| `reasoning_summary` | string | Concise account of the inspected path. |
| `assumptions_and_open_questions` | array of strings | Unverified prerequisites or missing information. |
| `verification_targets` | array of strings | Code locations or questions for independent review. |

A `CANDIDATE` requires a concrete weakness and supporting code references before independent review. `NO_FINDING` records a completed investigation without a supported candidate. `INSUFFICIENT_EVIDENCE` leaves the investigation unresolved.

Illustrative example:

```json
{
  "route_id": "example:route_1",
  "handler_ref": "example:handler_1",
  "decision": "INSUFFICIENT_EVIDENCE",
  "hypothesized_weakness": null,
  "sensitive_operation_ref": null,
  "auth_check_refs": [],
  "evidence_refs": ["example:indirect_call_site"],
  "reasoning_summary": "The indirect target on the request path is unresolved.",
  "assumptions_and_open_questions": ["Determine the indirect target."],
  "verification_targets": ["example:indirect_call_site"]
}
```

## Reviewer Agent

| Field | Type | Meaning |
| --- | --- | --- |
| `route_id` | string | Recovered route reference. |
| `finding_ref` | string | Detective candidate reference. |
| `decision` | string | `SUPPORTED`, `REJECTED`, or `UNRESOLVED`. |
| `verified_weakness` | string or null | Mechanism supported by independently inspected static evidence. |
| `supporting_evidence_refs` | array of strings | Independently checked code locations. |
| `counterevidence_refs` | array of strings | Code that contradicts the candidate. |
| `unresolved_assumptions` | array of strings | Remaining conditions the binary evidence cannot establish. |
| `review_summary` | string | Explanation of the decision. |

`SUPPORTED` requires static evidence for the route-to-handler mapping, sensitive operation, and proposed failure. Contradicting code leads to `REJECTED`; missing essential evidence leads to `UNRESOLVED`. The Reviewer has no runtime-test input or runtime-validation output field. Researchers perform subsequent PoC validation as described in the [evaluation protocol](../docs/evaluation_protocol.md).

Illustrative example:

```json
{
  "route_id": "example:route_1",
  "finding_ref": "example:candidate_1",
  "decision": "UNRESOLVED",
  "verified_weakness": null,
  "supporting_evidence_refs": ["example:dispatch_reference"],
  "counterevidence_refs": [],
  "unresolved_assumptions": ["The indirect target remains unknown."],
  "review_summary": "The available code does not establish the complete path."
}
```

These four examples explain formatting only. They are not measurements, confirmed vulnerabilities, or outputs from an evaluated device.
