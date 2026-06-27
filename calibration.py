"""
phishbyte/calibration.py
Threshold calibration via ROC analysis.

The cascade engine has two confidence gates per layer (phish gate + clean gate).
Hardcoded thresholds (0.85, 0.25) aren't defensible in research. This module
learns optimal thresholds from a validation set using two principled criteria:

  1.  PHISH gate  → threshold that achieves target precision (default 0.95)
                    "When we say phishing, we want to be right 95% of the time."
  2.  CLEAN gate  → threshold that achieves target recall on legitimate class
                    "When we say safe, we want to miss almost no real phish."

Operating points are computed by sweeping all possible thresholds and picking
the ones that hit the precision/recall targets while maintaining good
separation. Falls back to Youden's J statistic (max TPR − FPR) if targets
cannot be met on the given validation set.
"""

from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict
import json
import numpy as np


@dataclass
class ThresholdConfig:
    """Calibrated thresholds for one layer of the cascade."""
    layer:              str
    phish_threshold:    float
    clean_threshold:    float
    phish_precision:    float
    clean_recall:       float
    youden_j:           float
    coverage:           float
    notes:              str

    def to_dict(self) -> dict:
        return asdict(self)


def _sweep_thresholds(
    scores: np.ndarray,
    labels: np.ndarray,
    n_steps: int = 200,
) -> List[Tuple[float, float, float, float, float]]:
    """
    Sweep candidate thresholds. For each one compute:
        (threshold, precision_phish, recall_phish, recall_clean, fpr)
    Returns list sorted ascending by threshold.
    """
    rows = []
    for t in np.linspace(0.0, 1.0, n_steps + 1):
        preds = (scores >= t).astype(int)
        tp = int(((preds == 1) & (labels == 1)).sum())
        fp = int(((preds == 1) & (labels == 0)).sum())
        tn = int(((preds == 0) & (labels == 0)).sum())
        fn = int(((preds == 0) & (labels == 1)).sum())

        precision_phish = tp / (tp + fp + 1e-8)
        recall_phish    = tp / (tp + fn + 1e-8)
        recall_clean    = tn / (tn + fp + 1e-8)
        fpr             = fp / (fp + tn + 1e-8)

        rows.append((float(t), precision_phish, recall_phish, recall_clean, fpr))
    return rows


def calibrate_layer(
    scores: np.ndarray,
    labels: np.ndarray,
    layer_name: str           = "layer1",
    target_precision: float   = 0.95,
    target_clean_recall: float = 0.95,
) -> ThresholdConfig:
    """
    Calibrate one layer's two thresholds against a validation set.

    Parameters
    ----------
    scores               (N,) array of model scores in [0, 1].
    labels               (N,) array of 0/1 ground truth labels.
    layer_name           Identifier for logging.
    target_precision     Min precision for the PHISH gate.
                         Higher = stricter "definitely phishing" call.
    target_clean_recall  Min recall on legitimate class for the CLEAN gate.
                         Higher = stricter "definitely safe" call.

    Returns
    -------
    ThresholdConfig with phish_threshold, clean_threshold, and the metrics
    that justify them. Both bundled into one object that gets saved alongside
    the model weights.
    """
    scores = np.asarray(scores, dtype=np.float32)
    labels = np.asarray(labels, dtype=np.int64)

    if len(scores) != len(labels):
        raise ValueError("scores and labels must have same length")
    if len(scores) < 20:
        raise ValueError(f"Need at least 20 val samples to calibrate, got {len(scores)}")

    rows = _sweep_thresholds(scores, labels)

    # ── Phish gate ─────────────────────────────────────────────────────────
    # Lowest threshold that still achieves target precision.
    # (Lower threshold = higher recall while still meeting precision bar.)
    phish_t      = None
    phish_prec   = 0.0
    for t, prec, rec, _, _ in rows:
        if prec >= target_precision and rec > 0.1:
            phish_t     = t
            phish_prec  = prec
            break

    # ── Clean gate ─────────────────────────────────────────────────────────
    # Highest threshold where clean_recall still meets target.
    # (Higher threshold = more emails routed through cheap layer.)
    clean_t       = None
    clean_recall  = 0.0
    for t, _, _, cr, _ in reversed(rows):
        if cr >= target_clean_recall:
            clean_t       = t
            clean_recall  = cr
            break

    # ── Fallback: Youden's J statistic ─────────────────────────────────────
    # If targets unreachable on this val set, default to optimal single point.
    youden = max(rows, key=lambda r: r[2] - r[4])    # max(TPR - FPR)
    youden_j = youden[2] - youden[4]
    youden_t = youden[0]

    notes = ""
    if phish_t is None:
        phish_t    = min(0.85, youden_t + 0.1)
        phish_prec = next((p for t,p,_,_,_ in rows if t >= phish_t), 0.0)
        notes += f"phish target {target_precision:.2f} unmet, fallback used. "
    if clean_t is None:
        clean_t      = max(0.15, youden_t - 0.1)
        clean_recall = next((cr for t,_,_,cr,_ in reversed(rows) if t <= clean_t), 0.0)
        notes += f"clean target {target_clean_recall:.2f} unmet, fallback used. "
    if phish_t <= clean_t:
        mid = (phish_t + clean_t) / 2
        phish_t = mid + 0.05
        clean_t = mid - 0.05
        notes += "Thresholds crossed, separated around midpoint. "

    # Coverage = fraction of val samples decided by this layer alone
    decided = ((scores >= phish_t) | (scores <= clean_t)).sum()
    coverage = float(decided) / len(scores)

    return ThresholdConfig(
        layer            = layer_name,
        phish_threshold  = round(float(phish_t), 4),
        clean_threshold  = round(float(clean_t), 4),
        phish_precision  = round(float(phish_prec), 4),
        clean_recall     = round(float(clean_recall), 4),
        youden_j         = round(float(youden_j), 4),
        coverage         = round(coverage, 4),
        notes            = notes.strip() or "Targets met cleanly.",
    )


def save_thresholds(configs: Dict[str, ThresholdConfig], path: str):
    """Save calibrated thresholds to JSON alongside model weights."""
    payload = {name: cfg.to_dict() for name, cfg in configs.items()}
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def load_thresholds(path: str) -> Dict[str, ThresholdConfig]:
    """Load thresholds previously saved by save_thresholds()."""
    with open(path, "r") as f:
        payload = json.load(f)
    return {name: ThresholdConfig(**data) for name, data in payload.items()}