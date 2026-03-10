# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This project implements Claude Code hooks — specifically an allowlist-based network guard that intercepts Bash commands before execution and blocks calls to untrusted external endpoints.

## Commands

```bash
# Run the hook test suite
python3 test_hook.py

# Test the hook script directly with piped JSON
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' | python3 .claude/hooks/check_external_strings.py
```

## Architecture

### Hook System

- `.claude/settings.json` — Registers the `PreToolUse` hook (matcher: `Bash`) that runs before every Bash tool call
- `.claude/hooks/check_external_strings.py` — The hook handler. Reads JSON from stdin, returns a `permissionDecision` (`allow`/`deny`/`ask`) as JSON on stdout

### Hook Logic (allowlist-based)

The hook uses a **deny-by-default** model with three checks in order:

1. **Sensitive data scan** — Always blocks commands containing API keys, tokens, private keys, or credentials, regardless of target host
2. **Network call detection** — Matches patterns for curl, wget, requests, httpx, fetch, axios, nc, ssh, etc.
3. **Host allowlist check** — Extracts hostnames from URLs; blocks any host not in `TRUSTED_ENDPOINTS`

If no network call is detected, the command is allowed. If a network tool is found but the host can't be extracted (e.g. `$VAR`), the hook escalates to the user with `"ask"`.

### Adding Trusted Endpoints

Edit `TRUSTED_ENDPOINTS` in `.claude/hooks/check_external_strings.py`. Patterns are regexes matched with `re.fullmatch`. Default trusted: localhost, package registries (PyPI, npm, crates.io), and VCS hosts (GitHub, GitLab, Bitbucket).
