"""GLiNER plugin — zero-shot NER, flexible labels, ~18ms latency."""

from .base import DetectionResult, SensitiveContentPlugin


class GLiNERPlugin(SensitiveContentPlugin):
    name = "gliner"
    tier = "ZeroShot"

    def __init__(self):
        self._model = None
        self._model_name = "urchade/gliner_medium-v2.1"
        self._threshold = 0.5
        self._labels = [
            "person", "email", "phone number",
            "social security number", "credit card", "api key",
        ]

    def configure(self, plugin_config: dict) -> None:
        self._model_name = plugin_config.get("model", self._model_name)
        self._threshold = plugin_config.get("threshold", self._threshold)
        self._labels = plugin_config.get("labels", self._labels)

    def is_available(self) -> bool:
        try:
            from gliner import GLiNER  # noqa: F401
            return True
        except ImportError:
            return False

    def _get_model(self):
        if self._model is None:
            from gliner import GLiNER
            self._model = GLiNER.from_pretrained(self._model_name)
        return self._model

    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        model = self._get_model()
        labels = [l.lower() for l in entity_types] if entity_types else self._labels
        entities = model.predict_entities(text, labels, threshold=self._threshold)
        return [
            DetectionResult(
                entity_type=e["label"].upper(),
                text=e["text"],
                score=e["score"],
                start=e.get("start", 0),
                end=e.get("end", 0),
                plugin_name=self.name,
            )
            for e in entities
        ]
