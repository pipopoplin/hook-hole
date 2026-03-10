"""Microsoft Presidio plugin — known PII, sub-millisecond latency."""

from .base import DetectionResult, SensitiveContentPlugin


class PresidioPlugin(SensitiveContentPlugin):
    name = "presidio"
    tier = "SubMillisecond"

    def __init__(self):
        self._analyzer = None
        self._languages = ["en"]
        self._score_threshold = 0.6

    def configure(self, plugin_config: dict) -> None:
        self._languages = plugin_config.get("languages", ["en"])
        self._score_threshold = plugin_config.get("score_threshold", 0.6)

    def is_available(self) -> bool:
        try:
            import presidio_analyzer  # noqa: F401
            return True
        except ImportError:
            return False

    def _get_analyzer(self):
        if self._analyzer is None:
            from presidio_analyzer import AnalyzerEngine
            self._analyzer = AnalyzerEngine()
        return self._analyzer

    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        analyzer = self._get_analyzer()
        kwargs = {"text": text, "language": self._languages[0]}
        if entity_types:
            kwargs["entities"] = entity_types
        results = analyzer.analyze(**kwargs)
        return [
            DetectionResult(
                entity_type=r.entity_type,
                text=text[r.start:r.end],
                score=r.score,
                start=r.start,
                end=r.end,
                plugin_name=self.name,
            )
            for r in results
            if r.score >= self._score_threshold
        ]
