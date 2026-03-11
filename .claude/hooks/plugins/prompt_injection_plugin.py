"""Prompt injection / jailbreak detection plugin — heuristic + keyword, ~1ms latency."""

import re

from .base import DetectionResult, SensitiveContentPlugin

# Semantic patterns that complement the L1 regex rules.
# These catch paraphrased or obfuscated injection attempts.
INJECTION_PATTERNS = [
    # Role manipulation
    (r"\byou\s+are\s+now\s+(a|an|in)\b", "role_reassignment"),
    (r"\bact\s+as\s+(a|an|if)\b", "role_reassignment"),
    (r"\bpretend\s+(you\s+are|to\s+be|you'?re)\b", "role_reassignment"),
    (r"\brole\s*:\s*system\b", "role_override"),
    (r"\bsystem\s*:\s*you\s+are\b", "system_prompt_override"),
    # Instruction override
    (r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|guidelines?)", "instruction_override"),
    (r"\b(disregard|forget|override|bypass)\s+(your|all|the|any)\s+(instructions?|rules?|safety|guardrails?|filters?|restrictions?)", "instruction_override"),
    (r"\bnew\s+instructions?\s*:", "instruction_injection"),
    # Jailbreak keywords
    (r"\bjailbreak\b", "jailbreak_keyword"),
    (r"\bDAN\s+(mode|prompt)\b", "jailbreak_dan"),
    (r"\bdo\s+anything\s+now\b", "jailbreak_dan"),
    (r"\b(sudo|admin)\s+mode\b", "privilege_escalation"),
    (r"\bno\s+(restrictions?|limitations?|rules?|guardrails?)\b", "remove_restrictions"),
    # Structural injection
    (r"<\s*/?\s*(system|prompt|instruction|context)\s*>", "xml_tag_injection"),
    (r"\[\s*INST\s*\]", "instruction_tag"),
    (r"###\s*(system|instruction|human|assistant)\s*:", "markdown_role_injection"),
    # Exfiltration prompts
    (r"\b(reveal|show|print|output|display)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?|config)", "exfiltration_prompt"),
    (r"\bwhat\s+are\s+your\s+(instructions?|rules?|guidelines?)\b", "exfiltration_prompt"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label) for p, label in INJECTION_PATTERNS]


class PromptInjectionPlugin(SensitiveContentPlugin):
    name = "prompt_injection"
    tier = "EdgeDevice"

    def __init__(self):
        self._score_threshold = 0.6

    def configure(self, plugin_config: dict) -> None:
        self._score_threshold = plugin_config.get("score_threshold", 0.6)

    def is_available(self) -> bool:
        return True  # Pure Python, no external dependencies

    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        if entity_types and "PROMPT_INJECTION" not in entity_types:
            return []

        results = []
        seen_labels = set()

        for pattern, label in _COMPILED:
            for match in pattern.finditer(text):
                if label in seen_labels:
                    continue
                seen_labels.add(label)
                results.append(DetectionResult(
                    entity_type="PROMPT_INJECTION",
                    text=match.group(),
                    score=0.9,
                    start=match.start(),
                    end=match.end(),
                    plugin_name=self.name,
                ))

        return results
