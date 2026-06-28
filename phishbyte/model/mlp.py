"""
phishbyte/model/mlp.py
Layer 2 — PhishByte MLP classifier (v2).

Changes from v1
───────────────
  • Input dim: 15 → 23 (added 5 subject features + 1 brand impersonation + 1 subject layer score + 1 reserved)
  • Hidden: 64 → 96 (wider for richer feature set)
"""

import torch
import torch.nn as nn
from typing import Dict, List


FEATURE_NAMES: List[str] = [
    # Domain (5)
    "domain_mismatch",
    "replyto_differs",
    "returnpath_differs",
    "from_is_freemail",
    "brand_impersonation",
    # URL (5)
    "http_ratio",
    "anchor_mismatch_score",
    "suspicious_tld_score",
    "urgency_score",
    "link_density_score",
    # SPF (3)
    "spf_fail",
    "no_spf_record",
    "no_sending_ip",
    # Subject (7)
    "subject_urgency",
    "subject_security",
    "subject_brand_name",
    "subject_currency",
    "subject_all_caps",
    "subject_fake_re",
    "subject_fake_txn_id",
    # Composite layer scores (4)
    "domain_layer_score",
    "url_layer_score",
    "spf_layer_score",
    "subject_layer_score",
]

INPUT_DIM  = len(FEATURE_NAMES)   # 24
HIDDEN_DIM = 96


class PhishByteMLPLayer(nn.Module):
    """
    Shallow MLP for phishing email classification.

    Architecture
    ────────────
    Input (24) → Linear → BatchNorm → ReLU → Dropout(0.3)
              → Linear → BatchNorm → ReLU → Dropout(0.2)
              → Linear → Sigmoid → P(phish)
    """

    def __init__(
        self,
        input_dim:  int   = INPUT_DIM,
        hidden_dim: int   = HIDDEN_DIM,
        dropout1:   float = 0.3,
        dropout2:   float = 0.2,
    ):
        super().__init__()
        self.feature_names = FEATURE_NAMES
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout1),

            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout2),

            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid(),
        )
        self._init_weights()

    def _init_weights(self):
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, nonlinearity="relu")
                if module.bias is not None:
                    nn.init.zeros_(module.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)

    def predict_proba(self, x: torch.Tensor) -> float:
        self.eval()
        with torch.no_grad():
            if x.dim() == 1:
                x = x.unsqueeze(0)
            return self.forward(x).item()

    def get_config(self) -> Dict:
        return {
            "model_type":    "PhishByteMLP",
            "version":       "2.0",
            "input_dim":     INPUT_DIM,
            "hidden_dim":    HIDDEN_DIM,
            "feature_names": FEATURE_NAMES,
            "output":        "P(phish) sigmoid scalar",
            "framework":     "pytorch",
        }


def build_feature_vector(
    domain_result:  Dict,
    url_result:     Dict,
    spf_result:     Dict,
    subject_result: Dict,
) -> torch.Tensor:
    """Assemble the 24-dimensional feature vector from Layer 1 outputs."""
    d = domain_result["features"]
    u = url_result["features"]
    s = spf_result["features"]
    sub = subject_result["features"]

    vec = [
        d["domain_mismatch"], d["replyto_differs"], d["returnpath_differs"],
        d["from_is_freemail"], d["brand_impersonation"],
        u["http_ratio"], u["anchor_mismatch_score"], u["suspicious_tld_score"],
        u["urgency_score"], u["link_density_score"],
        s["spf_fail"], s["no_spf_record"], s["no_sending_ip"],
        sub["subject_urgency"], sub["subject_security"], sub["subject_brand_name"],
        sub["subject_currency"], sub["subject_all_caps"], sub["subject_fake_re"],
        sub["subject_fake_txn_id"],
        domain_result["score"], url_result["score"], spf_result["score"],
        subject_result["score"],
    ]
    return torch.tensor(vec, dtype=torch.float32)