#!/usr/bin/env python3
"""
Claude Code Hook: NLP-based sensitive content detection.

A plugin-based PreToolUse hook that uses NLP models to detect PII and
sensitive content in tool input. Complements the regex_filter for
catching content that pattern matching cannot.

Usage:
  python3 llm_filter.py <config.json>

Plugins (selected via config, first available wins):
  presidio   — Microsoft Presidio, ~0.4ms, known PII types
  distilbert — DistilBERT/NerGuard, ~25ms, best accuracy
  spacy      — spaCy sm + regex, ~3ms, edge/low-resource
"""

import importlib
import json
import os
import sys

def load_plugin_registry(hooks_dir: str) -> dict:
    """Load plugin registry from plugins/plugins.json."""
    registry_path = os.path.join(hooks_dir, "plugins", "plugins.json")
    if not os.path.isfile(registry_path):
        return {}
    with open(registry_path) as f:
        data = json.load(f)
    return {
        name: (info["module"], info["class"])
        for name, info in data.get("plugins", {}).items()
    }


def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def resolve_field(data: dict, field: str) -> str:
    current = data
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return ""
    return str(current) if current is not None else ""


def load_plugin(name: str, plugin_config: dict, registry: dict):
    """Load and configure a plugin by name. Returns None if unavailable."""
    if name not in registry:
        return None

    module_path, class_name = registry[name]
    try:
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        instance = cls()
        instance.configure(plugin_config.get(name, {}))
        if not instance.is_available():
            return None
        return instance
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        print("Usage: llm_filter.py <config.json>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expandvars(sys.argv[1])
    if not os.path.isfile(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Add hooks dir to path so plugins package is importable
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    if hooks_dir not in sys.path:
        sys.path.insert(0, hooks_dir)

    config = load_config(config_path)
    registry = load_plugin_registry(hooks_dir)

    if not config.get("enabled", True):
        sys.exit(0)

    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    field = config.get("field", "tool_input.command")
    text = resolve_field(hook_input, field)
    if not text:
        sys.exit(0)

    priority = config.get("plugin_priority", ["presidio", "spacy", "distilbert"])
    supplementary = config.get("supplementary_plugins", ["prompt_injection"])
    plugin_configs = config.get("plugins", {})
    min_confidence = config.get("min_confidence", 0.7)
    action = config.get("action", "deny")
    entity_types = config.get("entity_types")

    all_findings = []
    reporting_plugin = None

    # Find first available PII plugin and run detection
    for plugin_name in priority:
        if plugin_name in supplementary:
            continue
        if not plugin_configs.get(plugin_name, {}).get("enabled", True):
            continue

        plugin = load_plugin(plugin_name, plugin_configs, registry)
        if plugin is None:
            continue

        try:
            detections = plugin.detect(text, entity_types)
        except Exception as e:
            print(f"Plugin {plugin_name} error: {e}", file=sys.stderr)
            continue

        findings = [d for d in detections if d.score >= min_confidence]
        if findings:
            all_findings.extend(findings)
            reporting_plugin = plugin
        break  # first_available: only try the first working PII plugin

    # Run supplementary plugins (e.g. prompt injection) independently
    for plugin_name in supplementary:
        if not plugin_configs.get(plugin_name, {}).get("enabled", True):
            continue

        plugin = load_plugin(plugin_name, plugin_configs, registry)
        if plugin is None:
            continue

        try:
            detections = plugin.detect(text, entity_types)
        except Exception as e:
            print(f"Plugin {plugin_name} error: {e}", file=sys.stderr)
            continue

        findings = [d for d in detections if d.score >= min_confidence]
        if findings:
            all_findings.extend(findings)
            if reporting_plugin is None:
                reporting_plugin = plugin

    if not all_findings:
        sys.exit(0)

    findings_text = "\n".join(
        f"  - {d.entity_type}: '{d.text}' (confidence: {d.score:.2f})"
        for d in all_findings
    )

    hook_event = hook_input.get("hook_event_name", "PreToolUse")

    if hook_event == "PreToolUse":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny" if action == "deny" else "ask",
                "permissionDecisionReason": (
                    f"Sensitive content detected by {reporting_plugin.name} ({reporting_plugin.tier}):\n"
                    f"{findings_text}"
                ),
            }
        }
    else:
        output = {
            "decision": "block" if action == "deny" else action,
            "reason": f"Sensitive content detected by {reporting_plugin.name}:\n{findings_text}",
        }

    json.dump(output, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
