# PANGU

<!-- Copyright (c) 2026 The Pangu Project Authors. All rights reserved. -->

Source code for the paper: **"PANGU: Semantics-Aware Logic Decoupling for Broken Access Control Detection in Embedded Systems"**

PANGU is a static analysis framework leveraging semantic-aware logic decoupling to detect BAC vulnerabilities.

---

## Quick Start

### Requirements

- Python 3.8+
- IDA Pro 9.0+ (with Hex-Rays decompiler)
- OpenAI API Key (or compatible API), or a human/agent using the file review workflow below

### Installation

```bash
git clone https://github.com/tiger5671/PANGU.git
cd pangu
pip install -r requirements.txt

# Set environment variables
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # Optional
export OPENAI_MODEL="your-model-name"
```

### IDA Pro Setup

1. Open target binary in IDA Pro
2. Run the bridge server script:

```python
# In IDA Pro Python console
import sys, runpy
repo = r"D:\tiger\PANGU"  # Replace with your checkout path
sys.path[:0] = [repo, repo + r"\core\bridge"]
if "pangu_bridge" in globals():
    pangu_bridge["server_agent"].stop()
pangu_bridge = runpy.run_path(repo + r"\core\bridge\ida_server.py")
```

The server listens on port 4455 by default.

---

## Usage

### Full Pipeline

```bash
python PANGU.py --firmware "Device_Name" --phase all --verbose
```

### Phase-by-Phase Execution

```bash
# Phase 0: Firmware pre-analysis (no IDA required)
python PANGU.py -f "Device_Name" -p 0 --firmware-root "/path/to/squashfs-root"

# Phase 1: Route extraction (requires IDA)
python PANGU.py -f "Device_Name" -p 1

# Phase 2: Logic decoupling (requires IDA)
python PANGU.py -f "Device_Name" -p 2

# Phase 3: Vulnerability detection (requires IDA + LLM)
python PANGU.py -f "Device_Name" -p 3
```

### Command Line Arguments

#### Required Arguments

| Argument | Description |
|----------|-------------|
| `-f, --firmware` | Firmware identifier used for naming output files |

#### Optional Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-p, --phase` | Phase to run: `0`, `1`, `2`, `3`, or `all` | `all` |
| `-o, --output` | Output directory | `output` |
| `-v, --verbose` | Enable verbose output (shows intermediate results, LLM reasoning, etc.) | `False` |
| `--ida-port` | IDA server port | `4455` |
| `-r, --rag` | Enable RAG knowledge base for enhanced detection | `False` |
| `--ida-snapshot` | Replay recorded IDA queries; missing queries return errors | - |
| `--review-mailbox` | Directory for file-based human/agent review; no model API needed | - |
| `--storage-graph` | Candidate storage channels; firmware ID must match `--firmware` | - |
| `--max-routes` | Phase 3 route budget; `0` means all, deferred routes appear in the report | `50` |

#### Phase-Specific Arguments

| Argument | Phase | Description | Default |
|----------|-------|-------------|---------|
| `--firmware-root` | 0 | Path to extracted firmware filesystem (e.g., squashfs-root). Required for Phase 0. | - |
| `-a, --arch` | 1 | Web server architecture: `auto`, `goahead`, `fastcgi`, `jsonrpc`, `goform` | `auto` |
| `--init-func` | 2 | Web initialization function name (e.g., `sub_423F90`) | - |

### IDA Snapshots and File Review

Export read-only evidence using headless IDA. The binary/database is copied to a temporary directory before analysis; choose function names that actually exist in the input.

```powershell
python scripts/ida_snapshot.py "path/to/binary" --ida-path "D:/software/IDA_Pro9.0/idat.exe" --functions main --output output/evidence.json
```

Additional bounded read queries can be supplied through `--queries queries.json`, containing an array such as `[{"command":"get_functions","params":{}}]`. Add `--storage` to collect constant NVRAM keys. A snapshot only answers recorded queries; collect additional evidence when a query is missing.

With an existing `output/Device_Name_acdg.json`, Phase 3 can use file review without API credentials:

```powershell
python PANGU.py -f Device_Name -p 3 --ida-snapshot output/evidence.json --review-mailbox output/review --max-routes 1
```

When a response is missing, the command writes `<hash>.request.json`, prints the expected response path and exits with code `2`. A human or agent reads the request and evidence, then writes `<hash>.response.json` in this form:

```json
{"request_id": "<hash from request>", "response": {"fields": "use the schema in the request messages"}}
```

The example shows the envelope only; the response must follow that request's actual schema. Rerun the same command to continue. Changed prompts or evidence require a new response. This mode does not automatically invoke a model; a reviewer must supply each response. Live IDA can also be used by omitting `--ida-snapshot`.

To join storage evidence from binaries in the same firmware:

```powershell
python scripts/link_storage_snapshots.py output/binary_a.json output/binary_b.json --firmware-id Device_Name --output output/storage.json
```

These links are candidate channels, not verified taint flows. Pass the result as `--storage-graph output/storage.json` during Phase 3.

### Local Tests

```bash
python -m pytest -q
```

The default suite runs unit tests and mock integration tests. It does not replace live IDA/model evaluation. See the progress record for completed checks and remaining validation.

---

## Output Files

Results are saved in the `output/` directory:

| File | Phase | Description |
|------|-------|-------------|
| `{firmware}_preanalysis.json` | 0 | Web server type, config paths, static routes |
| `{firmware}_routes.json` | 1 | Route-to-handler mappings |
| `{firmware}_acdg.json` | 2 | Access Control Dependency Graph with auth states |
| `{firmware}_vulnerabilities.json` | 3 | Findings supported by static evidence and review |
| `{firmware}_detection_report.json` | 3 | Coverage, evidence budgets, supported and unresolved findings |
| `{firmware}_vulnerability_report_{timestamp}.json` | 3 | Timestamped detection report |

`Auth-Required` records the presence of a check, not its effectiveness. All auth states remain eligible for investigation. `UNRESOLVED` results and deferred routes require further analysis; supported findings still need appropriate independent validation.

---

## Project Structure

```
PANGU/
├── PANGU.py                  # Main entry point
├── README.md
├── reproducibility/           # Paper artifacts and evaluation metadata
├── requirements.txt
│
├── analysis/                 # Analysis modules
│   ├── models.py             # Data models (ACDG, RouteNode, etc.)
│   ├── firmware_analyzer.py  # Phase 0: Firmware pre-analysis
│   ├── route_extractor.py    # Phase 1: Route extraction
│   ├── fastcgi_extractor.py  # Phase 1: FastCGI extractor
│   ├── goform_extractor.py   # Phase 1: GoForm extractor
│   ├── jsonrpc_extractor.py  # Phase 1: JSON-RPC extractor
│   ├── ssi_extractor.py      # Phase 1: SSI/CGI extractor
│   ├── logic_decoupler.py    # Phase 2: Logic decoupling
│   ├── detective_agent.py    # Phase 3: Detective Agent
│   ├── reviewer_agent.py     # Phase 3: Reviewer Agent
│   ├── dual_agent_detector.py # Phase 3: Dual-Agent coordinator
│   └── pangu_pipeline.py     # Pipeline orchestrator
│
├── core/                     # Core infrastructure
│   ├── llm.py                # LLM API wrapper
│   └── bridge/               # IDA Pro bridge
│       ├── ida_client.py     # RPC client
│       ├── ida_server.py     # IDA plugin server
│       ├── cfg_analysis.py   # CFG analysis
│       └── static_analysis.py
│
├── rag/                      # RAG knowledge base
│   └── knowledge_base.py
│
├── tests/                    # Test suite
├── scripts/                  # Utility scripts
└── output/                   # Analysis results
```

---

## Research artifacts

The materials accompanying the revised paper are available in [reproducibility/](reproducibility/README.md):

- [Evaluation firmware inventory](reproducibility/dataset/README.md): 42 firmware images from 13 vendors and 78 known benchmark CVE references, in Markdown, JSON, and the original Excel workbook.
- [Official firmware source portals](reproducibility/dataset/vendor_sources.md): vendor support/download references, with the available metadata and its limits.
- [Four prompt templates](reproducibility/prompts/README.md), [reported model settings](reproducibility/prompts/model_configuration.json), and [output formats](reproducibility/prompts/output_formats.md).
- [Analysis definitions](reproducibility/docs/analysis_definitions.md), including ACDG semantics and TIS counting rules, and the [evaluation protocol](reproducibility/docs/evaluation_protocol.md).
- [Artifact availability](reproducibility/docs/artifact_availability.md), including the disclosure status of materials for unpatched findings.

The Detective and Reviewer perform static binary analysis. Researchers subsequently construct PoCs and validate supported findings on physical devices or through QEMU-based emulation. The newly discovered vulnerabilities are reported separately from the known-vulnerability benchmark.

Run the material checks from the repository root:

```bash
python reproducibility/scripts/validate_materials.py
```

This command checks the published inventory and documentation files without IDA or an API key. It does not rerun the firmware experiments.

See the [artifact update notes](RESEARCH_ARTIFACTS_UPDATE_20261106.md) for the scope of this documentation release.

---

## Ethical Considerations

As detailed in our paper, PANGU has successfully uncovered 34 previously unknown BAC vulnerabilities in commercial IoT firmware.  **Controlled Release Strategy:** To balance open science transparency with the ethical obligation to protect real-world systems from unintended misuse, we have adopted a controlled release strategy for data containing sensitive technical details. Firmware samples, PoC exploits, and specific vulnerable configurations associated with unpatched issues are temporarily withheld in accordance with Coordinated Vulnerability Disclosure (CVD) practices. These artifacts will be fully released to this repository only after the respective vendors have completed their remediation processes.

------

## License

This project is for academic research purposes only.
