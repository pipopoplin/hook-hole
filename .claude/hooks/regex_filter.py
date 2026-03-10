#!/usr/bin/env python3
"""
Claude Code Hook: General-purpose regex filter.

A configurable PreToolUse hook that applies regex rules to tool input.
Rules are loaded from a JSON config file. Each rule matches a regex against
a field from the hook input and returns a decision (allow/deny/ask).

Usage:
  python3 regex_filter.py <config.json>

Config format: see .claude/hooks/filter_rules.json
"""

import json
import os
import re
import sys


def load_config(path: str) -> dict:
    """Load and validate the filter config."""
    with open(path) as f:
        config = json.load(f)
    if "rules" not in config:
        print(f"Config missing 'rules' key: {path}", file=sys.stderr)
        sys.exit(1)
    return config


def resolve_field(data: dict, field: str) -> str:
    """Resolve a dot-separated field path from the hook input JSON.

    e.g. "tool_input.command" -> data["tool_input"]["command"]
    """
    parts = field.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return ""
    return str(current) if current is not None else ""


def evaluate_rules(rules: list[dict], hook_input: dict) -> dict | None:
    """Evaluate rules in order. Returns first matching deny/ask, or None."""
    for rule in rules:
        if not rule.get("enabled", True):
            continue

        field = rule.get("field", "tool_input.command")
        value = resolve_field(hook_input, field)
        if not value:
            continue

        # Check tool_name filter if specified
        tool_filter = rule.get("tool_name")
        if tool_filter:
            actual_tool = hook_input.get("tool_name", "")
            if not re.search(tool_filter, actual_tool, re.IGNORECASE):
                continue

        action = rule.get("action", "deny")
        patterns = rule.get("patterns", [])
        match_mode = rule.get("match", "any")  # "any" or "all"

        matches = []
        for entry in patterns:
            if isinstance(entry, str):
                pattern, label = entry, entry
            elif isinstance(entry, dict):
                pattern, label = entry["pattern"], entry.get("label", entry["pattern"])
            else:
                continue

            if re.search(pattern, value, re.IGNORECASE):
                matches.append(label)

        triggered = False
        if match_mode == "any" and matches:
            triggered = True
        elif match_mode == "all" and len(matches) == len(patterns):
            triggered = True

        if not triggered:
            continue

        # For "allow" rules, return immediately to skip further checks
        if action == "allow":
            return {"decision": "allow"}

        reason = rule.get("message", "Blocked by regex filter rule.")
        if matches:
            reason += "\nMatched:\n" + "\n".join(f"  - {m}" for m in matches)

        return {
            "decision": action,
            "reason": reason,
        }

    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: regex_filter.py <config.json>", file=sys.stderr)
        sys.exit(1)

    config_path = sys.argv[1]
    # Support $CLAUDE_PROJECT_DIR in the path
    config_path = os.path.expandvars(config_path)

    if not os.path.isfile(config_path):
        print(f"Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = load_config(config_path)

    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    result = evaluate_rules(config["rules"], hook_input)

    if result is None or result["decision"] == "allow":
        sys.exit(0)

    hook_event = hook_input.get("hook_event_name", "PreToolUse")

    if hook_event == "PreToolUse":
        decision_map = {"deny": "deny", "ask": "ask", "block": "deny"}
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision_map.get(result["decision"], "deny"),
                "permissionDecisionReason": result["reason"],
            }
        }
    else:
        output = {
            "decision": "block" if result["decision"] == "deny" else result["decision"],
            "reason": result["reason"],
        }

    json.dump(output, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
