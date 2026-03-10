# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Claude Code hook system with two complementary security layers:
1. **regex_filter** — fast, deterministic regex rules for endpoint allowlisting and credential detection
2. **llm_filter** — NLP-based PII detection with pluggable backends (Presidio, spaCy, GLiNER, DistilBERT)

Both run as `PreToolUse` hooks on `Bash` commands. The regex filter runs first (<1ms), the NLP filter second (3-25ms depending on plugin).

## Commands

```bash
# Run all tests
python3 test_hook.py && python3 test_llm_hook.py

# Test regex filter directly
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' | python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules.json

# Test NLP filter directly
echo '{"tool_name":"Bash","tool_input":{"command":"send to john@example.com"}}' | python3 .claude/hooks/llm_filter.py .claude/hooks/llm_filter_config.json

# Install NLP plugin (pick one)
pip install spacy && python -m spacy download en_core_web_sm
```

## Architecture

### Hook Pipeline

`.claude/settings.json` registers two `PreToolUse` hooks (matcher: `Bash`) that run in sequence:

```
Bash command → regex_filter.py (rules) → llm_filter.py (NLP) → execute or block
```

### Regex Filter

- `.claude/hooks/regex_filter.py` — General-purpose regex engine. Reads any JSON rule config, evaluates rules top-to-bottom, first match wins.
- `.claude/hooks/filter_rules.json` — Shipped rules: (1) block sensitive data, (2) allow trusted endpoints, (3) block untrusted network calls.

Rule format: `field` (dot-path into hook JSON), `action` (allow/deny/ask), `match` (any/all), `patterns` (regex list), optional `tool_name` filter and `enabled` toggle.

### NLP Filter

- `.claude/hooks/llm_filter.py` — Plugin-based NLP hook. Loads plugin registry and detection config, tries plugins in priority order, uses first available.
- `.claude/hooks/llm_filter_config.json` — Plugin priority, confidence thresholds, entity types, per-plugin settings.
- `.claude/hooks/plugins/plugins.json` — Plugin registry. Maps names to module/class paths. Add custom plugins here without touching Python code.
- `.claude/hooks/plugins/base.py` — `SensitiveContentPlugin` ABC and `DetectionResult` dataclass.
- `.claude/hooks/plugins/{presidio,gliner,distilbert,spacy}_plugin.py` — Backend implementations.

### Adding Trusted Endpoints

Add a pattern to `allow_trusted_endpoints` in `.claude/hooks/filter_rules.json`:
```json
{"pattern": "https?://api\\.your-company\\.com", "label": "Your API"}
```

### Adding a Custom NLP Plugin

1. Create `.claude/hooks/plugins/my_plugin.py` extending `SensitiveContentPlugin`
2. Register in `.claude/hooks/plugins/plugins.json`
3. Enable and configure in `.claude/hooks/llm_filter_config.json`
