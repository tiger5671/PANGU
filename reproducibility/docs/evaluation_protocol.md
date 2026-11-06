# Evaluation protocol

## Populations and labeling

The route and authentication-labeling assessments use different populations.

| Assessment | Population | Criterion and reported result |
| --- | --- | --- |
| Route mapping | An approximately 5% random sample of all 13,128 recovered interfaces. | Inspect the local dispatch key, parent registration context, dispatch transition, and handler identity against the binary. Accuracy is correct mappings divided by inspected mappings; the reported value is 98.2%. |
| Auth-Free labeling | All 166 predicted Auth-Free interfaces. | Confirm a prediction when no authentication-related checkpoint is identified within the binary-analysis scope. The 160 confirmed predictions give precision `160 / 166 = 96.4%` after rounding. |
| Routing depth | The 11 devices in the route-reconstruction comparison table. | Average their maximum recovered depths: `24 / 11`, reported as 2.2. This is not an average over all 42 images. |

The 13,128 recovered interfaces consist of 12,962 Auth-Required and 166 Auth-Free interfaces. A checkpoint that is present but bypassable still counts as present for authentication-state labeling. Its enforcement behavior is examined in vulnerability analysis.

Two researchers first inspect the routes independently using the same criteria. They revisit disagreements together using registration sites, dispatch cross-references, dominators, and handler control flow, and agree on a final label from the code evidence.

The supplied records give an approximately 5% route sample but not its exact size, membership, or random seed. Do not infer an integer sample count from the rounded percentage and accuracy.

## Known-vulnerability matching and counting

The benchmark has 78 independent known vulnerabilities. Matching uses the affected component, the recovered entry/handler and access-control context, and the underlying unauthorized behavior in the analyzed image. A product name or overlapping version range alone is insufficient to establish a match.

The counting unit is an independent vulnerability mechanism in its affected evaluation context. Repeated reports or multiple routes for the same defect are consolidated. Preserve the distinction between an advisory's affected-version range and the identity of the image actually analyzed.

## Manual validation after static analysis

1. Researchers inspect a supported finding's entry point, reachable handler, access-control predicates, and protected operation.
2. They construct an issue-specific PoC request or test case.
3. They execute it on the corresponding physical device when available, otherwise using QEMU-based firmware or service emulation.
4. They compare the observed response and program behavior with the predicted unauthorized operation.

The agents supply static-analysis findings. Researchers perform the PoC construction and runtime validation after the agent analysis. This procedure does not imply that every firmware image was tested using both a physical device and QEMU.

## TP, FP, FN, and aggregate results

A true positive matches a known benchmark issue and is supported by inspection and PoC validation. A false negative is a known benchmark issue that was not detected. A false positive is a reported hypothesis rejected by manual inspection and PoC/runtime verification.

For the known benchmark, PANGU reports 71 TP, 12 FP, and 7 FN:

```text
precision = 71 / (71 + 12) = 85.5% after rounding
recall    = 71 / 78        = 91.0% after rounding
```

The 34 newly discovered vulnerabilities are evaluated separately. Their novelty is checked against public records, and they follow the same manual inspection and PoC validation process. The paper reports 32 CVE assignments and two unassigned findings. CVE assignment records the disclosure outcome, not a separate validation criterion.

## Ablation variants

| Variant | Analysis retained | TP / FP / FN | Precision / recall (%) | Time (min) |
| --- | --- | --- | --- | --- |
| PANGU | ACDG guidance, tool-using Detective, independent Reviewer. | 71 / 12 / 7 | 85.5 / 91.0 | 883 |
| PANGU-LLM | ACDG guidance and the Detective's tools and iterative reasoning; the Reviewer stage is removed. | 33 / 55 / 45 | 37.5 / 42.3 | 84 |
| PANGU-Naive | Recovered route-to-handler mappings without Logic Decoupling/ACDG guidance. | 9 / 55 / 69 | 14.1 / 11.5 | 1,558 |

The PANGU-LLM comparison measures the Reviewer stage as a whole, including its tool calls and iterative analysis. PANGU-Naive sometimes stops before completing its larger search under the evaluated time/token budgets. Its results therefore include the effects of incomplete execution.

These are the paper's reported aggregate measurements. This material update does not report a new experiment run.
