# PANGU research artifacts

These materials accompany *PANGU: Semantics-Aware Logic Decoupling for Broken Access Control Detection in Embedded Systems*. They document the evaluation firmware, four LLM analysis stages, and the methods used to interpret the reported results.

| Material | Contents |
| --- | --- |
| [Firmware inventory](dataset/README.md) | All 42 evaluated images from 13 vendors and their 78 known benchmark CVE references; Markdown, JSON, and the original Excel workbook. |
| [Firmware sources](dataset/vendor_sources.md) | Official support/download portals for the 13 vendors, with the limits of these references stated explicitly. |
| [Prompt templates](prompts/README.md) | Route classification, security-check classification, Detective investigation, and independent Reviewer verification. |
| [Model configuration](prompts/model_configuration.json) | The reported model, parameter-override policy, and request retry limit. |
| [Output formats](prompts/output_formats.md) | Fields, labels, and interpretation of the four parameterized templates. |
| [Analysis definitions](docs/analysis_definitions.md) | Context backtracking, ACDG semantics, and TIS counting and termination rules. |
| [Evaluation protocol](docs/evaluation_protocol.md) | Assessment populations, vulnerability matching and validation, metrics, and ablation variants. |
| [Artifact availability](docs/artifact_availability.md) | What is included and which experimental materials are not part of this release. |

The Detective and Reviewer use static binary-analysis evidence. Researchers subsequently construct and run PoC tests on physical devices or in QEMU to validate supported findings. An agent's `SUPPORTED` decision is a static-analysis outcome.

The templates are parameterized documentation of the analysis stages. The JSON configuration records the reported experimental settings; copying it into a repository does not configure the application automatically. See the main project README for installation and execution.

To check the inventory, template fields, example JSON, and file checksums without IDA or an API key, run from the repository root:

```bash
python reproducibility/scripts/validate_materials.py
```

The check validates these materials. It does not rerun the firmware experiments or establish that an application loads the documented templates.
