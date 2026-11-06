# Analysis definitions

## Hierarchical context backtracking

Start with a validated local dispatch key, its handler, and its containing registration or dispatcher scope. Trace handler/table cross-references to the enclosing registration site, prepend the supported parent prefix, and continue toward the global request-dispatch root.

- Stop at the identified global root.
- If the parent cannot be resolved, retain the last supported partial route and its resolution level.
- Stop a chain when a context repeats or traversal makes no progress.
- Follow distinct supported parent registrations separately and deduplicate identical route-handler pairs.

For example, `addUserBookmark` registered under `/goform` gives `/goform/addUserBookmark`. If that dispatcher is mounted under `/api`, another step gives `/api/goform/addUserBookmark`. The extra `/api` level is an illustrative mount, not an additional measured device route.

Action selectors are evaluated by their dispatch semantics. They need not occur as literal complete URL strings.

## ACDG representation and labels

The ACDG is an attributed routing graph `G = (V_R, E_R, alpha)`:

| Element | Meaning |
| --- | --- |
| Route node in `V_R` | Recovered interface or logical dispatch sequence, with handler and request-time dispatch context. A parent prefix may be a routing context without being a separately invocable endpoint. |
| Directed edge in `E_R` | Supported parent-child registration or dispatch relation. |
| `alpha(v)`, stored as `auth_refs` | Code references to identified authentication/authorization checkpoints applicable to route `v`. |
| `auth_state` | `Auth-Required` when `auth_refs` is nonempty; otherwise `Auth-Free` within the analysis scope. |

The routing edges are not CFG edges, call edges, or security-check vertices. Check references are node attributes.

Global-check association uses ordinary intra-procedural dominance when the checkpoint and dispatch site share a function CFG. Across functions, association additionally requires a verified request-time forwarding/call context through the protected global dispatch point. A routing edge alone does not establish dominance. Local references come from the handler's candidate guards after semantic verification.

A flawed or bypassable check remains in `auth_refs` and can leave a route labeled Auth-Required. The subsequent Detective and Reviewer analysis examines the predicate, failure path, alternative entries, and sensitive operation. Auth-Free alone is not a vulnerability finding.

## TIS statement units

For a conditional `n`, TIS compares the normalized static sizes of its two branch-specific continuations:

```text
TIS(n) = max(size_then, size_else) / (min(size_then, size_else) + 1)
         * I(the shorter continuation terminates the request)
```

Regions start at the conditional's successors and end at their common continuation or request-exit boundary. Exclude shared prefix/suffix code from both sizes. When there is no syntactic `else`, use the other CFG successor as the fall-through continuation.

| C-tree construct | Normalized weight |
| --- | --- |
| Assignment, call, return, goto, or break | 1 per executable leaf statement. |
| `if` | 1 for the condition plus the recursively counted branch bodies. |
| Compound block | Sum of its statements. An explicitly represented empty branch has a minimum structural weight of 1. |
| `while` or `do` loop | Fixed weight 3, without expanding the body or multiplying iterations. |
| `for` loop | Fixed weight 3, plus 1 each for an explicit initializer and updater. |
| Label, brace, comment, or declaration without executable initialization | 0. |

Calls are counted at the call site without expanding the callee. Loops are not unrolled.

## Termination and screening

A shorter continuation terminates only if it exits the request handler or reaches a verified non-returning exit without returning to protected processing. For `goto` and `break`, inspect the resolved destination. A loop-local `break` normally resumes the surrounding request. Shared cleanup can establish termination while remaining excluded from both sizes. Indirect calls require a resolved target or dependable non-return metadata. Unreliable decompilation or unresolved control flow does not establish termination.

The reported threshold is `tau_tis = 5.0`, with the strict test `TIS > 5.0`. It was selected by inspecting representative authentication and ordinary early-exit branches. The source materials provide the selection rationale, not a calibration dataset or threshold-sweep log.

The Case-II worked example has branch weights 2 and 118 and a terminating shorter continuation, giving `118 / (2 + 1) = 39.3` after rounding. High TIS selects a guard candidate; semantic classification determines whether it serves authentication, authorization, or another purpose.

## Scope

Route recovery depends on supported binary dispatch patterns. Opaque indirect callbacks, obfuscated or runtime-generated dispatch, external scripts/services, and authorization dependent on other processes or unavailable state can remain unresolved. The reconstructed tree and Auth-Free labels refer to the represented binary-analysis scope.
