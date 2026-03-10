"""spaCy + regex plugin — edge/low-resource, ~3ms latency."""

import re

from .base import DetectionResult, SensitiveContentPlugin

# spaCy NER labels relevant to PII (ignore noisy labels like WORK_OF_ART, EVENT, etc.)
SPACY_PII_LABELS = {"PERSON", "ORG", "GPE", "NORP"}

# Regex patterns for structured PII that spaCy's NER won't catch
REGEX_PATTERNS = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL_ADDRESS"),
    (r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", "US_SSN"),
    (r"\b(?:\d[ -]*?){13,16}\b", "CREDIT_CARD"),
    (r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "PHONE_NUMBER"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP_ADDRESS"),
]


class SpaCyPlugin(SensitiveContentPlugin):
    name = "spacy"
    tier = "EdgeDevice"

    def __init__(self):
        self._nlp = None
        self._model_name = "en_core_web_sm"
        self._extra_patterns = True

    def configure(self, plugin_config: dict) -> None:
        self._model_name = plugin_config.get("model", self._model_name)
        self._extra_patterns = plugin_config.get("extra_patterns", True)

    def is_available(self) -> bool:
        try:
            import spacy  # noqa: F401
            spacy.load(self._model_name)
            return True
        except (ImportError, OSError):
            return False

    def _get_nlp(self):
        if self._nlp is None:
            import spacy
            self._nlp = spacy.load(self._model_name)
        return self._nlp

    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        results = []

        # spaCy NER — only PII-relevant labels, skip short/noisy matches
        nlp = self._get_nlp()
        doc = nlp(text)
        for ent in doc.ents:
            entity_type = ent.label_.upper()
            if entity_type not in SPACY_PII_LABELS:
                continue
            if entity_types and entity_type not in entity_types:
                continue
            # Skip false positives common in shell commands
            if (ent.text.startswith("-")
                    or len(ent.text) < 3
                    or "--" in ent.text
                    or len(ent.text) > len(text) * 0.5):
                continue
            results.append(DetectionResult(
                entity_type=entity_type,
                text=ent.text,
                score=0.75,  # spaCy sm has moderate accuracy; reflect that
                start=ent.start_char,
                end=ent.end_char,
                plugin_name=self.name,
            ))

        # Regex patterns for structured PII
        if self._extra_patterns:
            for pattern, entity_type in REGEX_PATTERNS:
                if entity_types and entity_type not in entity_types:
                    continue
                for match in re.finditer(pattern, text):
                    results.append(DetectionResult(
                        entity_type=entity_type,
                        text=match.group(),
                        score=0.95,
                        start=match.start(),
                        end=match.end(),
                        plugin_name=self.name,
                    ))

        return results
