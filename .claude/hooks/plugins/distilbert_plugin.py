"""DistilBERT / NerGuard plugin — highest accuracy NER, ~25ms latency."""

from .base import DetectionResult, SensitiveContentPlugin


class DistilBERTPlugin(SensitiveContentPlugin):
    name = "distilbert"
    tier = "HighAccuracy"

    def __init__(self):
        self._pipeline = None
        self._model_name = "dslim/distilbert-NER"
        self._score_threshold = 0.8

    def configure(self, plugin_config: dict) -> None:
        self._model_name = plugin_config.get("model", self._model_name)
        self._score_threshold = plugin_config.get("score_threshold", self._score_threshold)

    def is_available(self) -> bool:
        try:
            import transformers  # noqa: F401
            return True
        except ImportError:
            return False

    def _get_pipeline(self):
        if self._pipeline is None:
            from transformers import pipeline
            self._pipeline = pipeline(
                "ner",
                model=self._model_name,
                aggregation_strategy="simple",
            )
        return self._pipeline

    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        pipe = self._get_pipeline()
        ner_results = pipe(text)
        results = []
        for r in ner_results:
            if r["score"] < self._score_threshold:
                continue
            entity_type = r["entity_group"].upper()
            if entity_types and entity_type not in entity_types:
                continue
            results.append(DetectionResult(
                entity_type=entity_type,
                text=r["word"],
                score=r["score"],
                start=r.get("start", 0),
                end=r.get("end", 0),
                plugin_name=self.name,
            ))
        return results
