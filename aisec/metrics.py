"""Detection-quality metrics for the aisec-suite regression corpus."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int

    @property
    def precision(self) -> float:
        d = self.true_positive + self.false_positive
        return self.true_positive / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.true_positive + self.false_negative
        return self.true_positive / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def false_positive_rate(self) -> float:
        d = self.false_positive + self.true_negative
        return self.false_positive / d if d else 0.0

    def to_dict(self) -> dict[str, float | int]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "false_negative": self.false_negative,
            "true_negative": self.true_negative,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


def evaluate(expected_vulnerable: set[str], detected: set[str], expected_clean: set[str] | None = None) -> DetectionMetrics:
    """Evaluate case IDs, keeping vulnerable and clean expectations explicit."""
    expected_clean = expected_clean or set()
    tp = len(expected_vulnerable & detected)
    fn = len(expected_vulnerable - detected)
    fp = len(detected & expected_clean)
    tn = len(expected_clean - detected)
    return DetectionMetrics(tp, fp, fn, tn)
