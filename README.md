# PANGU

<!-- Copyright (c) 2026 The Pangu Project Authors. All rights reserved. -->

Source code for the paper: **"Pangu: Semantic-Enhanced Logic Decoupling for Broken Access Control Detection in Embedded Systems"**

PANGU is a static analysis framework leveraging semantic-enhanced logic decoupling to detect BAC vulnerabilities.

---

## Quick Start

### Requirements

- Python 3.8+
- IDA Pro 9.0+ (with Hex-Rays decompiler)
- OpenAI API Key (or compatible API)

### Installation

```bash
git clone https://github.com/anonymous/pangu.git
cd pangu
pip install -r requirements.txt

# Set environment variables
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # Optional
```

### IDA Pro Setup

1. Open target binary in IDA Pro
2. Run the bridge server script:

```python
# In IDA Pro Python console
exec(open("path/to/core/bridge/ida_server.py").read())
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

#### Phase-Specific Arguments

| Argument | Phase | Description | Default |
|----------|-------|-------------|---------|
| `--firmware-root` | 0 | Path to extracted firmware filesystem (e.g., squashfs-root). Required for Phase 0. | - |
| `-a, --arch` | 1 | Web server architecture: `auto`, `goahead`, `fastcgi`, `jsonrpc`, `goform` | `auto` |
| `--init-func` | 2 | Web initialization function name (e.g., `sub_423F90`) | - |

---

## Output Files

Results are saved in the `output/` directory:

| File | Phase | Description |
|------|-------|-------------|
| `{firmware}_preanalysis.json` | 0 | Web server type, config paths, static routes |
| `{firmware}_routes.json` | 1 | Route-to-handler mappings |
| `{firmware}_acdg.json` | 2 | Access Control Dependency Graph with auth states |
| `{firmware}_findings.json` | 3 | Detected vulnerabilities with CWE mappings |
| `{firmware}_analysis_report.md` | all | Comprehensive analysis report |

---

## Project Structure

```
PANGU/
├── PANGU.py                  # Main entry point
├── README.md
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

## License

This project is for academic research purposes only.
