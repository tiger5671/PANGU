# Research artifacts for the revised PANGU manuscript

This update adds the firmware inventory, parameterized prompt templates, reported model settings, and analysis/evaluation documentation accompanying the revised manuscript.

- The inventory covers 42 firmware images from 13 vendors and their 78 known benchmark CVE references. The original Excel workbook is included with Markdown and JSON views.
- Official firmware support/download portals are listed separately from the image inventory. Exact binary URLs and image hashes are not supplied by this metadata release.
- Four prompt templates document route classification, security-check classification, Detective investigation, and independent static Reviewer verification. Output-field descriptions and illustrative JSON responses are included.
- Model configuration records `gpt-4.1`, the absence of explicit sampling/output-length overrides, and at most three total request attempts.
- Methods documentation explains routing reconstruction, ACDG check-presence labels, TIS counting and termination, evaluation populations, manual validation, and ablation variants.
- A Python script validates the material set without IDA, network access, or an API key.

The templates and configuration are documentation artifacts. This update does not change the analysis implementation or report new experimental results. Firmware redistribution and release of details for unpatched findings follow the availability statement.
