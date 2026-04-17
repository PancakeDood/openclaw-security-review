# Methodology

This project implements a lightweight static analysis pipeline to support the security review of orchestration frameworks such as OpenClaw. The tool recursively scans source code and configuration files, matches lines against a curated set of security rules, and outputs findings in terminal, JSON, and Markdown formats.

## Scope

The tool is intended to identify **candidate risks** for further manual review. It does not prove exploitability or confirm that every finding is a real vulnerability.

## Rule Categories

- Command Execution Risks
- Secrets Exposure
- Input Validation Risks
- Authentication / Authorization Risks
- Logging / Audit Weaknesses

## Limitations

- Pattern matching may generate false positives.
- Context-sensitive security issues may be missed.
- Findings should be manually validated before being reported as real vulnerabilities.
