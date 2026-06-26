"""
phishbyte/model/mlp.py
Layer 2 — PhishByte MLP classifier.
Fully custom PyTorch architecture. No pretrained weights.
Input: 15-dimensional feature vector from Layer 1 extractors.
Output: P(phish) scalar in [0, 1].
"""

import torch
import torch.nn as nn
from typing import Dict, List


# ── Feature vector schema ────────────────────────────────────────────────────
# These are the 15 features in exact order the MLP expects.
# Any change here must be mirrored in engine.py build_feature_vector().
FEATURE_NAMES: List[str] = [
    # Domain features (4)
    "domain_mismatch",
    "replyto_differs",
    "returnpath_differs",
    "from_is_freemail",
    # URL features (5)
    "http_ratio",
    "anchor_mismatch_score",
    "suspicious_tld_score",
    "urgency_score",
    "link_density_score",
    # SPF features (3)
    "spf_fail",
    "no_spf_record",
    "no_sending_ip",
    # Composite Layer 1 scores (3)
    "domain_layer_score",
    "url_layer_score",
    "spf_layer_score",
]

INPUT_DIM  = len(FEATURE_NAMES)   # 15
HIDDEN_DIM = 64
OUTPUT_DIM = 1


class PhishByteMLPLayer(nn.Module):
    """
    Shallow MLP for phishing email classification.

    Architecture
    ────────────
    Input (15)
        → Linear(15 → 64) → BatchNorm → ReLU → Dropout(0.3)
        → Linear(64 → 32) → BatchNorm → ReLU → Dropout(0.2)
        → Linear(32 → 1)  → Sigmoid
    Output: P(phish) in [0, 1]
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
            # Block 1
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout1),

            # Block 2
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout2),

            # Output head
            nn.Linear(hidden_dim // 2, OUTPUT_DIM),
            nn.Sigmoid(),
        )

        self._init_weights()

    def _init_weights(self):
        """Kaiming init for ReLU layers, Xavier for output."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, nonlinearity="relu")
                if module.bias is not None:
                    nn.init.zeros_(module.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Parameters
        ----------
        x : torch.Tensor  shape (batch_size, 15)

        Returns
        -------
        torch.Tensor  shape (batch_size, 1)  — P(phish) per sample
        """
        return self.net(x)

    def predict_proba(self, x: torch.Tensor) -> float:
        """Single-sample inference. Returns P(phish) as a Python float."""
        self.eval()
        with torch.no_grad():
            if x.dim() == 1:
                x = x.unsqueeze(0)            # (1, 15)
            return self.forward(x).item()

    def get_config(self) -> Dict:
        """Return architecture config for HuggingFace / PyTorch Hub model card."""
        return {
            "model_type":    "PhishByteMLP",
            "input_dim":     INPUT_DIM,
            "hidden_dim":    HIDDEN_DIM,
            "feature_names": FEATURE_NAMES,
            "output":        "P(phish) sigmoid scalar",
            "framework":     "pytorch",
        }


def build_feature_vector(
    domain_result: Dict,
    url_result:    Dict,
    spf_result:    Dict,
) -> torch.Tensor:
    """
    Assemble the 15-dimensional feature vector from Layer 1 scorer outputs.
    Returns a float32 tensor of shape (15,).
    """
    d = domain_result["features"]
    u = url_result["features"]
    s = spf_result["features"]

    vec = [
        # Domain (4)
        d["domain_mismatch"],
        d["replyto_differs"],
        d["returnpath_differs"],
        d["from_is_freemail"],
        # URL (5)
        u["http_ratio"],
        u["anchor_mismatch_score"],
        u["suspicious_tld_score"],
        u["urgency_score"],
        u["link_density_score"],
        # SPF (3)
        s["spf_fail"],
        s["no_spf_record"],
        s["no_sending_ip"],
        # Composite layer scores (3)
        domain_result["score"],
        url_result["score"],
        spf_result["score"],
    ]

    return torch.tensor(vec, dtype=torch.float32)