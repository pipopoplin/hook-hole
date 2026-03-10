#!/usr/bin/env python3
"""
Claude Code Hook: Allowlist-based external service guard.

This PreToolUse hook intercepts Bash commands and blocks any network call
to an endpoint that is NOT on the trusted allowlist. Sensitive data patterns
(API keys, tokens, etc.) are always blocked regardless of endpoint.

Hook type: PreToolUse (matcher: Bash)
Input: JSON on stdin with tool_name and tool_input
Output: JSON decision (allow/deny/ask) on stdout

Configure TRUSTED_ENDPOINTS below to add your allowed hosts.
"""

import json
import re
import sys

# --- Configuration ---

# Trusted endpoints: network calls to these hosts are ALLOWED.
# Everything else is BLOCKED. Regex patterns matched against URLs in the command.
TRUSTED_ENDPOINTS = [
    r"localhost(:\d+)?",
    r"127\.0\.0\.1(:\d+)?",
    r"::1(:\d+)?",
    r"0\.0\.0\.0(:\d+)?",
    r".*\.local(:\d+)?",
    # Package registries
    r"(registry\.)?npmjs\.(org|com)",
    r"pypi\.org",
    r"files\.pythonhosted\.org",
    r"rubygems\.org",
    r"crates\.io",
    r"packagist\.org",
    r"pkg\.go\.dev",
    # Version control
    r"github\.com",
    r"gitlab\.com",
    r"bitbucket\.org",
    # --- Add your trusted endpoints below ---
    # r"api\.your-company\.com",
    # r"internal\.myservice\.io",
]

# Patterns that indicate a network call is being made
NETWORK_PATTERNS = [
    # curl (any form)
    r"\bcurl\b",
    # wget
    r"\bwget\b",
    # httpie
    r"\bhttp\b\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)",
    # Python HTTP libraries
    r"requests\.(get|post|put|patch|delete|head)\s*\(",
    r"httpx\.(get|post|put|patch|delete|head)\s*\(",
    r"urllib\.request\.(urlopen|urlretrieve)\s*\(",
    r"aiohttp\.ClientSession",
    r"http\.client\.(HTTPConnection|HTTPSConnection)",
    # Node.js / JS
    r"\bfetch\s*\(",
    r"axios\.(get|post|put|patch|delete)\s*\(",
    r"https?\.request\s*\(",
    # Anthropic / OpenAI SDK calls
    r"anthropic\.",
    r"openai\.",
    r"client\.messages\.create\s*\(",
    r"client\.chat\.completions\.create\s*\(",
    # Generic network tools
    r"\bnc\b\s+",
    r"\bnetcat\b",
    r"\bsocat\b",
    r"\btelnet\b",
    r"\bssh\b\s+",
    r"\bscp\b\s+",
    r"\brsync\b\s+.*:",
    r"\bnmap\b",
    # Piping to network tools
    r"\|\s*curl\b",
    r"\|\s*nc\b",
    r"\|\s*netcat\b",
]

# URL extraction pattern
URL_PATTERN = re.compile(
    r"https?://([a-zA-Z0-9\-_.]+(?::\d+)?)[/\s'\"]?",
    re.IGNORECASE,
)

# Hostname from SSH-style patterns (user@host, host:path)
SSH_HOST_PATTERN = re.compile(
    r"(?:[\w]+@)?([a-zA-Z0-9\-_.]+):",
)

# Sensitive data patterns — ALWAYS blocked, even to trusted endpoints
SENSITIVE_PATTERNS = [
    (r"sk-ant-[a-zA-Z0-9\-]+", "Anthropic API key"),
    (r"sk-(?:proj-)?[a-zA-Z0-9]{20,}", "OpenAI-style API key"),
    (r"ANTHROPIC_API_KEY\s*=\s*['\"]?[a-zA-Z0-9]", "Anthropic API key assignment"),
    (r"OPENAI_API_KEY\s*=\s*['\"]?[a-zA-Z0-9]", "OpenAI API key assignment"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key"),
    (r"(aws_access_key_id|aws_secret_access_key)\s*=\s*['\"]?[A-Z0-9]", "AWS credentials"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
    (r"xox[bpas]-[a-zA-Z0-9\-]+", "Slack token"),
    (r"(password|passwd|secret)\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded password/secret"),
]


def is_trusted(host: str) -> bool:
    """Check if a hostname matches any trusted endpoint pattern."""
    for pattern in TRUSTED_ENDPOINTS:
        if re.fullmatch(pattern, host, re.IGNORECASE):
            return True
    return False


def extract_hosts(command: str) -> list[str]:
    """Extract all hostnames from URLs and SSH-style patterns in a command."""
    hosts = []
    for match in URL_PATTERN.finditer(command):
        host = match.group(1)
        # Strip port for matching
        hosts.append(host)
    for match in SSH_HOST_PATTERN.finditer(command):
        host = match.group(1)
        if not host.startswith("-") and "." in host:
            hosts.append(host)
    return hosts


def has_network_call(command: str) -> bool:
    """Check if the command makes any kind of network call."""
    for pattern in NETWORK_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False


def check_sensitive_data(command: str) -> list[str]:
    """Check for sensitive data patterns. Returns list of findings."""
    findings = []
    for pattern, description in SENSITIVE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            findings.append(description)
    return findings


def analyze_command(command: str) -> dict:
    """Analyze a bash command. Returns decision dict."""

    # 1. Always check for sensitive data first
    sensitive_findings = check_sensitive_data(command)
    if sensitive_findings:
        return {
            "decision": "deny",
            "reason": (
                "Sensitive data detected in command:\n"
                + "\n".join(f"  - {f}" for f in sensitive_findings)
                + "\n\nRemove credentials before running this command."
            ),
        }

    # 2. Check if command makes a network call
    if not has_network_call(command):
        return {"decision": "allow"}

    # 3. Extract hosts and check against allowlist
    hosts = extract_hosts(command)

    if not hosts:
        # Network tool detected but no extractable host — ask user
        return {
            "decision": "ask",
            "reason": (
                "Network call detected but could not determine the target host.\n"
                f"Command: {command[:200]}\n\n"
                "Approve only if you trust the destination."
            ),
        }

    untrusted = [h for h in hosts if not is_trusted(h)]

    if not untrusted:
        # All hosts are trusted
        return {"decision": "allow"}

    return {
        "decision": "deny",
        "reason": (
            "Network call to untrusted endpoint(s):\n"
            + "\n".join(f"  - {h}" for h in untrusted)
            + "\n\nAllowed endpoints: localhost, package registries, github/gitlab/bitbucket.\n"
            "To allow this host, add it to TRUSTED_ENDPOINTS in:\n"
            "  .claude/hooks/check_external_strings.py"
        ),
    }


def main():
    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    result = analyze_command(command)

    if result["decision"] == "allow":
        sys.exit(0)

    if result["decision"] == "deny":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": result["reason"],
            }
        }
        json.dump(output, sys.stdout)
        sys.exit(0)

    if result["decision"] == "ask":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": result["reason"],
            }
        }
        json.dump(output, sys.stdout)
        sys.exit(0)


if __name__ == "__main__":
    main()
