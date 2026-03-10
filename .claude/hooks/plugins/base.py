"""Base class and types for sensitive content detection plugins."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    entity_type: str    # e.g. "PERSON", "EMAIL_ADDRESS", "CREDIT_CARD"
    text: str           # matched span
    score: float        # confidence 0.0-1.0
    start: int = 0
    end: int = 0
    plugin_name: str = ""


class SensitiveContentPlugin(ABC):
    name: str = ""
    tier: str = ""  # SubMillisecond | ZeroShot | HighAccuracy | EdgeDevice

    @abstractmethod
    def is_available(self) -> bool:
        """Check if required dependencies are installed."""

    @abstractmethod
    def detect(self, text: str, entity_types: list[str] | None = None) -> list[DetectionResult]:
        """Detect sensitive content. Returns list of findings."""

    def configure(self, plugin_config: dict) -> None:
        """Apply plugin-specific config. Override if needed."""
