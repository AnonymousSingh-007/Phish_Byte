"""
phishbyte/model/mlp.py — v3
29-input MLP: domain(5) + url(5) + spf(3) + subject(7) + char(5) + composite(4)
"""
import torch
import torch.nn as nn
from typing import Dict, List


FEATURE_NAMES: List[str] = [
    # Domain (5)
    "domain_mismatch", "replyto_differs", "returnpath_differs",
    "from_is_freemail", "brand_impersonation",
    # URL (5)
    "http_ratio", "anchor_mismatch_score", "suspicious_tld_score",
    "urgency_score", "link_density_score",
    # SPF (3)
    "spf_fail", "no_spf_record", "no_sending_ip",
    # Subject (7)
    "subject_urgency", "subject_security", "subject_brand_name",
    "subject_currency", "subject_all_caps", "subject_fake_re",
    "subject_fake_txn_id",
    # Char-level body (5) — vocabulary-agnostic
    "caps_ratio", "digit_ratio", "special_density",
    "avg_word_length", "html_text_ratio",
    # Composite scores (4)
    "domain_layer_score", "url_layer_score",
    "spf_layer_score",    "subject_layer_score",
]

INPUT_DIM  = len(FEATURE_NAMES)   # 29
HIDDEN_DIM = 128


class PhishByteMLPLayer(nn.Module):
    """
    Architecture: 29 → 128 → 64 → 1 (sigmoid)
    Wider than v2 to handle the richer feature space.
    """

    def __init__(self, input_dim=INPUT_DIM, hidden_dim=HIDDEN_DIM,
                 dropout1=0.3, dropout2=0.2):
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
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, nonlinearity="relu")
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x): return self.net(x)

    def predict_proba(self, x):
        self.eval()
        with torch.no_grad():
            if x.dim() == 1: x = x.unsqueeze(0)
            return self.forward(x).item()

    def get_config(self):
        return {
            "model_type":    "PhishByteMLP",
            "version":       "3.0",
            "input_dim":     INPUT_DIM,
            "hidden_dim":    HIDDEN_DIM,
            "feature_names": FEATURE_NAMES,
            "output":        "P(phish) sigmoid scalar",
            "framework":     "pytorch",
        }


def build_feature_vector(d_res, u_res, s_res, sub_res):
    d, u, s, sub = d_res["features"], u_res["features"], s_res["features"], sub_res["features"]
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