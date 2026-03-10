# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This project implements a general-purpose regex filter hook for Claude Code. It intercepts tool calls (e.g. Bash commands) and applies configurable regex rules to allow, deny, or escalate them. Rules are defined in a JSON config file, not hardcoded.

## Commands

```bash
# Run the hook test suite
python3 test_hook.py

# Test the filter directly with piped JSON
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' | python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules.json
```

## Architecture

### Hook System

- `.claude/settings.json` — Registers the `PreToolUse` hook (matcher: `Bash`) pointing to `regex_filter.py`
- `.claude/hooks/regex_filter.py` — General-purpose regex filter engine. Reads rules from a JSON config, evaluates them in order against hook input, and returns a `permissionDecision` (`allow`/`deny`/`ask`)
- `.claude/hooks/filter_rules.json` — Rule definitions. Rules are evaluated top-to-bottom; first match wins

### Rule Config Format

Each rule in `filter_rules.json` has:
- `field` — dot-path into the hook input JSON to match against (e.g. `tool_input.command`)
- `action` — `allow`, `deny`, or `ask`
- `match` — `any` (default) or `all` patterns must match
- `patterns` — list of regex strings or `{"pattern": "...", "label": "..."}` objects
- `tool_name` — optional regex to restrict the rule to specific tools
- `enabled` — optional, defaults to `true`

Rules are evaluated in order. First matching deny/ask rule wins, unless an `allow` rule matches first. The shipped config has three rules in this order: block sensitive data, allow trusted endpoints, block untrusted network calls.

### Adding Trusted Endpoints

Add a pattern to the `allow_trusted_endpoints` rule in `.claude/hooks/filter_rules.json`:
```json
{"pattern": "https?://api\\.your-company\\.com", "label": "Your API"}
```
