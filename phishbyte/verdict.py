from dataclasses import dataclass, field, asdict
from typing import Dict, Optional
import json

@dataclass
class PhishVerdict:
    label: str
    probability: float
    confidence: str
    layer_used: int
    feature_weights: Dict[str, float] = field(default_factory=dict)
    detail: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def __repr__(self):
        bar_len = int(self.probability * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        label_icon = "🚨 PHISHING" if self.label == "phishing" else "✅ LEGITIMATE"
        conf_color = {"high": "HIGH", "medium": "MED", "low": "LOW"}.get(self.confidence, "?")
        lines = [
            "─" * 52,
            f"  PHISH_BYTE ENGINE — VERDICT",
            "─" * 52,
            f"  {label_icon}",
            f"  P(phish): [{bar}] {self.probability:.2%}",
            f"  Confidence: {conf_color}   Layer used: {self.layer_used}",
            "─" * 52,
            "  FEATURE BREAKDOWN",
        ]
        for feat, score in sorted(self.feature_weights.items(), key=lambda x: -x[1]):
            bar2_len = int(score * 16)
            bar2 = "▓" * bar2_len + "░" * (16 - bar2_len)
            lines.append(f"  {feat:<28} [{bar2}] {score:.2f}")
        if self.detail:
            lines += ["─" * 52, f"  {self.detail}"]
        lines.append("─" * 52)
        return "\n".join(lines)