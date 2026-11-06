# Artifact availability

| Material | Availability in this update |
| --- | --- |
| Firmware inventory and known benchmark CVE references | Included for all 42 images, in Markdown, JSON, and the original workbook. |
| Four parameterized prompt templates | Included, together with their output fields and label definitions. |
| Reported LLM settings and retry policy | Included as documentation in `model_configuration.json`. |
| Analysis and evaluation definitions | Included in the methods and evaluation documents. |
| Official firmware support/download references | Included for all 13 vendors; exact historical binary downloads have not been verified. |
| PANGU implementation and execution instructions | Provided by the [main project repository](https://github.com/tiger5671/PANGU). This documentation update does not change the implementation. |
| Firmware binaries | Not included in this update. Redistribution depends on vendor permissions. |
| Sensitive firmware-to-new-finding mappings, detailed traces, and PoC scripts for unpatched issues | Withheld under the disclosure policy stated in the paper. |
| Exact binary hashes, archive filenames, and acquisition timestamps | Not present in the supplied inventory. |
| Route-sample membership, exact route-mapping sample count, random seed, per-device PoC logs, and threshold-calibration records | Not present in this material set. Aggregate results and the described procedure are provided; these underlying records have not been reconstructed. |

Known benchmark CVE associations in the inventory are distinct from the withheld mappings for unpatched newly discovered vulnerabilities.

The materials allow readers to inspect the data inventory, prompt interfaces, and evaluation definitions. Repeating the experiments additionally requires the relevant binaries, analysis environment, model access, and validation setup.
