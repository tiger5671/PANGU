# Prompt templates and settings

| Stage | Template | Accepted result and use |
| --- | --- | --- |
| Route classification | [Template](route_classification.txt) | URL_PATH / ACTION_MAP require supported dispatch and handler evidence; RESOURCE_MAP is excluded. UNRESOLVED is a processing status. |
| Security-check classification | [Template](security_check_verification.txt) | AUTHENTICATION / AUTHORIZATION enter checkpoint sets; NON_SECURITY is excluded; UNRESOLVED requires further inspection. |
| Detective | [Template](detective_agent.txt) | CANDIDATE / NO_FINDING / INSUFFICIENT_EVIDENCE, with concrete code references. |
| Reviewer | [Template](reviewer_agent.txt) | SUPPORTED / REJECTED / UNRESOLVED after independent static examination of the code and proposed failure path. |

[Model configuration](model_configuration.json) records `gpt-4.1`, no explicit overrides for temperature, top-p, or maximum output length, and a limit of three total attempts per request. No numerical default values or dated model snapshot have been inferred. This JSON file documents the reported settings; it is not an application configuration loader.

The caller fills braced placeholders with candidate records and retrieved binary-analysis evidence. These parameterized templates document the four analysis stages. Input values in braces, such as `{decompile, cfg, ...}`, may also enumerate the available tools. They are not a Python format specification.

The Reviewer uses static tools only. Researchers construct PoCs and run physical-device or QEMU tests after the agent analysis, as described in the [evaluation protocol](../docs/evaluation_protocol.md).

[Output formats](output_formats.md) lists the required fields and labels and gives an illustrative result for each stage. The examples are invented to explain the format; they are not reports from an evaluated device. Template variable names and these examples should not be taken as a claim about the current application's internal API.
