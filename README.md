# OpenClaw Security Review Toolkit

A lightweight static security analysis toolkit designed to support the security review of orchestration frameworks such as OpenClaw.

## What it does

This project scans source files and configuration files for potentially risky patterns related to:

- command execution
- hardcoded secrets
- unsafe input handling
- weak authentication or authorization clues
- missing logging and audit clues

It is designed as a **support tool** for structured security review, not as proof that every matched pattern is exploitable.

## Project Structure

```text
openclaw-security-review/
├── scanner/
│   ├── __init__.py
│   ├── main.py
│   ├── rules.py
│   ├── engine.py
│   ├── reporter.py
│   └── utils.py
├── sample_target/
├── output/
├── docs/
├── README.md
└── requirements.txt
```

## Requirements

- Python 3.10+
- No third-party dependencies are required for the core scanner

## Quick Start

### macOS / Linux

```bash
git clone <YOUR-REPO-URL>
cd openclaw-security-review
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m scanner.main ./sample_target
```

### Windows (PowerShell)

```powershell
git clone <YOUR-REPO-URL>
cd openclaw-security-review
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m scanner.main .\sample_target
```

## Example Output

The scanner writes:

- `output/findings.json`
- `output/findings.md`

## Limitations

- Regex-based matching can produce false positives.
- The tool does not execute code or verify exploitability.
- Findings should be manually reviewed before being treated as real vulnerabilities.

