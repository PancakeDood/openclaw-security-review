"""Security rules used by the OpenClaw Security Review Toolkit."""

RULES = [
    {
        "id": "CMD001",
        "category": "Command Execution Risks",
        "severity": "High",
        "pattern": r"os\.system\s*\(",
        "description": "Use of os.system may enable unsafe shell command execution.",
    },
    {
        "id": "CMD002",
        "category": "Command Execution Risks",
        "severity": "High",
        "pattern": r"subprocess\.(Popen|run|call)\s*\(.*shell\s*=\s*True",
        "description": "subprocess with shell=True may allow command injection.",
    },
    {
        "id": "CMD003",
        "category": "Command Execution Risks",
        "severity": "Medium",
        "pattern": r"paramiko\.SSHClient|exec_command\s*\(",
        "description": "Remote command execution should be carefully authenticated, authorized, and audited.",
    },
    {
        "id": "SEC001",
        "category": "Secrets Exposure",
        "severity": "High",
        "pattern": r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        "description": "Potential hardcoded secret or credential found in source or config.",
    },
    {
        "id": "SEC002",
        "category": "Secrets Exposure",
        "severity": "Medium",
        "pattern": r"(?i)BEGIN\s+(RSA|OPENSSH|DSA|EC)\s+PRIVATE\s+KEY",
        "description": "Potential embedded private key material.",
    },
    {
        "id": "INP001",
        "category": "Input Validation Risks",
        "severity": "High",
        "pattern": r"\beval\s*\(",
        "description": "Use of eval on untrusted input can lead to arbitrary code execution.",
    },
    {
        "id": "INP002",
        "category": "Input Validation Risks",
        "severity": "High",
        "pattern": r"\bexec\s*\(",
        "description": "Use of exec on untrusted input can lead to arbitrary code execution.",
    },
    {
        "id": "INP003",
        "category": "Input Validation Risks",
        "severity": "High",
        "pattern": r"yaml\.load\s*\([^\)]*Loader\s*=\s*yaml\.Loader|yaml\.load\s*\(",
        "description": "Unsafe YAML loading may deserialize attacker-controlled objects.",
    },
    {
        "id": "INP004",
        "category": "Input Validation Risks",
        "severity": "Medium",
        "pattern": r"pickle\.loads?\s*\(",
        "description": "Untrusted pickle deserialization is dangerous.",
    },
    {
        "id": "AUTH001",
        "category": "Authentication / Authorization Risks",
        "severity": "Medium",
        "pattern": r"(?i)(TODO|FIXME).*(auth|authentication|authorization|access control)",
        "description": "A comment may indicate incomplete or missing auth or access control protections.",
    },
    {
        "id": "AUTH002",
        "category": "Authentication / Authorization Risks",
        "severity": "High",
        "pattern": r"(?i)(debug\s*=\s*True|allow_anonymous\s*=\s*True|auth_disabled\s*=\s*True)",
        "description": "Debug or explicitly disabled auth setting found.",
    },
    {
        "id": "AUTH003",
        "category": "Authentication / Authorization Risks",
        "severity": "Medium",
        "pattern": r"@app\.(get|post|put|delete)\([^\n]*\)\s*\ndef\s+\w+\(",
        "description": "HTTP route found; review whether authentication and authorization are enforced.",
    },
    {
        "id": "AUD001",
        "category": "Logging / Audit Weaknesses",
        "severity": "Low",
        "pattern": r"(?i)(TODO|FIXME).*(log|logging|audit|monitor)",
        "description": "Comment may indicate missing logging, auditing, or monitoring work.",
    },
    {
        "id": "AUD002",
        "category": "Logging / Audit Weaknesses",
        "severity": "Medium",
        "pattern": r"(?i)(delete_all|reset_system|run_remote_command)",
        "description": "Sensitive operation keyword found; verify corresponding logging and audit coverage.",
    },
]

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env", ".conf", ".ini", ".txt"
}
