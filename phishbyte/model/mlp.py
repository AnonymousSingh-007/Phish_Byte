"""
phishbyte/model/mlp.py — v5 (50K params, residual connections)

Architecture upgrade from v4 (12K params, 128→64):
  29 → 256 → 128 → 64 → 1
  + residual shortcut: 256-layer output projected → added to 64-layer input
  Total params: ~50,400

Residual connection rationale:
  On a 29-feature tabular input, some layers may not learn useful
  transformations for certain feature combinations. The skip connection
  lets gradient flow directly when the layer isn't contributing,
  stabilizing training on varied phishing patterns across 6 datasets.
"""

import torch
import torch.nn as nn
from typing import Dict, List

from huggingface_hub import PyTorchModelHubMixin


FEATURE_NAMES: List[str] = [
    "domain_mismatch", "replyto_differs", "returnpath_differs",
    "from_is_freemail", "brand_impersonation",
    "http_ratio", "anchor_mismatch_score", "suspicious_tld_score",
    "urgency_score", "link_density_score",
    "spf_fail", "no_spf_record", "no_sending_ip",
    "subject_urgency", "subject_security", "subject_brand_name",
    "subject_currency", "subject_all_caps", "subject_fake_re",
    "subject_fake_txn_id",
    "caps_ratio", "digit_ratio", "special_density",
    "avg_word_length", "html_text_ratio",
    "domain_layer_score", "url_layer_score",
    "spf_layer_score", "subject_layer_score",
]

INPUT_DIM  = len(FEATURE_NAMES)   # 29
HIDDEN_1   = 192
HIDDEN_2   = 96
HIDDEN_3   = 48


class ResidualBlock(nn.Module):
    """
    Two-layer block with skip connection.
    Input and output have the same dimension.
    Used to stabilise training on varied feature distributions
    across the 6-corpus training set.
    """
    def __init__(self, dim: int, dropout: float = 0.2):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dim, dim),
            nn.BatchNorm1d(dim),
        )
        self.relu = nn.ReLU()

    def forward(self, x):
        return self.relu(self.block(x) + x)


class PhishByteMLPLayer(
    nn.Module,
    PyTorchModelHubMixin,
    library_name="phishbyte",
    repo_url="https://github.com/AnonymousSingh-007/Phish_Byte",
    docs_url="https://github.com/AnonymousSingh-007/Phish_Byte#readme",
    pipeline_tag="text-classification",
    license="mit",
    tags=[
        "phishing-detection", "email-security", "pytorch",
        "from-scratch", "no-pretrained-weights",
        "cascading-inference", "lightweight", "explainable-ai",
        "cybersecurity", "nlp", "phishing",
    ],
):
    """
    PhishByte MLP v5 — 50K parameter email phishing classifier.

    Architecture: 29 → 256 → ResBlock(128) → 64 → 1 (sigmoid)
    With residual projection: 256 → (proj to 64) + 128→64 stream

    Parameters:  ~50,400
    Trained on:  6-corpus benchmark (CEAS-2008, Enron, SpamAssassin,
                 Ling-Spam, Nazario, Nigerian Fraud)
    """

    def __init__(
        self,
        input_dim:  int   = INPUT_DIM,
        hidden_1:   int   = HIDDEN_1,
        hidden_2:   int   = HIDDEN_2,
        hidden_3:   int   = HIDDEN_3,
        dropout1:   float = 0.3,
        dropout2:   float = 0.2,
        dropout3:   float = 0.1,
    ):
        super().__init__()
        self.feature_names = FEATURE_NAMES
        self.input_dim = input_dim

        # Main stream: input → 256 → 128
        self.stream = nn.Sequential(
            nn.Linear(input_dim, hidden_1),
            nn.BatchNorm1d(hidden_1),
            nn.ReLU(),
            nn.Dropout(dropout1),

            nn.Linear(hidden_1, hidden_2),
            nn.BatchNorm1d(hidden_2),
            nn.ReLU(),
            nn.Dropout(dropout2),
        )

        # Residual block at 128 dim
        self.res_block = ResidualBlock(hidden_2, dropout=dropout2)

        # Projection from 128 → 64 (main path)
        self.proj_main = nn.Sequential(
            nn.Linear(hidden_2, hidden_3),
            nn.BatchNorm1d(hidden_3),
        )

        # Skip connection: project from input directly → 64
        # Lets gradients skip the entire deep stack when useful
        self.skip = nn.Sequential(
            nn.Linear(input_dim, hidden_3),
            nn.BatchNorm1d(hidden_3),
        )

        # Output head
        self.head = nn.Sequential(
            nn.ReLU(),
            nn.Dropout(dropout3),
            nn.Linear(hidden_3, 1),
            nn.Sigmoid(),
        )

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, nonlinearity="relu")
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: (batch, 29)  →  out: (batch, 1)  P(phish) in [0,1]
        """
        main = self.stream(x)              # (B, 256) → (B, 128)
        main = self.res_block(main)        # (B, 128)
        main = self.proj_main(main)        # (B, 64)
        skip = self.skip(x)                # (B, 64)
        return self.head(main + skip)      # residual merge

    def predict_proba(self, x: torch.Tensor) -> float:
        self.eval()
        with torch.no_grad():
            if x.dim() == 1:
                x = x.unsqueeze(0)
            return self.forward(x).item()

    def get_config(self) -> Dict:
        return {
            "model_type":    "PhishByteMLP",
            "version":       "5.0",
            "input_dim":     INPUT_DIM,
            "hidden_dims":   [HIDDEN_1, HIDDEN_2, HIDDEN_3],
            "residual":      True,
            "feature_names": FEATURE_NAMES,
            "output":        "P(phish) sigmoid scalar",
            "framework":     "pytorch",
        }


def build_feature_vector(d_res, u_res, s_res, sub_res) -> torch.Tensor:
    """Assemble 29-dim feature vector from Layer 1 scorer outputs."""
    d, u, s, sub = (
        d_res["features"], u_res["features"],
        s_res["features"], sub_res["features"]
    )
    vec = [
        d["domain_mismatch"], d["replyto_differs"], d["returnpath_differs"],
        d["from_is_freemail"], d["brand_impersonation"],
        u["http_ratio"], u["anchor_mismatch_score"], u["suspicious_tld_score"],
        u["urgency_score"], u["link_density_score"],
        s["spf_fail"], s["no_spf_record"], s["no_sending_ip"],
        sub["subject_urgency"], sub["subject_security"], sub["subject_brand_name"],
        sub["subject_currency"], sub["subject_all_caps"], sub["subject_fake_re"],
        sub["subject_fake_txn_id"],
        u["caps_ratio"], u["digit_ratio"], u["special_density"],
        u["avg_word_length"], u["html_text_ratio"],
        d_res["score"], u_res["score"], s_res["score"], sub_res["score"],
    ]
    return torch.tensor(vec, dtype=torch.float32)