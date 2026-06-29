"""
phishbyte/model/mlp.py — v4 (HuggingFace-ready)

The MLP now inherits from PyTorchModelHubMixin, giving it:
    - save_pretrained(local_dir)
    - push_to_hub(repo_id)
    - from_pretrained(repo_id or local_dir)

These three methods handle weights serialization (as safetensors) and
auto-generate a base model card. The engine wraps this and adds the
threshold loading logic.
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
    "spf_layer_score",    "subject_layer_score",
]

INPUT_DIM  = len(FEATURE_NAMES)   # 29
HIDDEN_DIM = 96


class PhishByteMLPLayer(
    nn.Module,
    PyTorchModelHubMixin,
    library_name="phishbyte",
    repo_url="https://github.com/AnonymousSingh-007/Phish_Byte",
    docs_url="https://github.com/AnonymousSingh-007/Phish_Byte#readme",
    pipeline_tag="text-classification",
    license="mit",
    tags=[
        "phishing-detection",
        "email-security",
        "pytorch",
        "from-scratch",
        "no-pretrained-weights",
        "cascading-inference",
        "lightweight",
    ],
):
    """
    PhishByte MLP — 29-feature email phishing classifier.

    Architecture: 29 → 96 → 48 → 1 (sigmoid)
    Parameters:   12,545
    Trained on:   CEAS-2008 (39,154 labeled emails)
    Test F1:      0.948

    Usage:
        >>> from phishbyte.model.mlp import PhishByteMLPLayer
        >>> model = PhishByteMLPLayer.from_pretrained("AnonymousSingh-007/phishbyte")
        >>> # ...or use the high-level engine wrapper:
        >>> from phishbyte import PhishByteEngine
        >>> engine = PhishByteEngine.from_pretrained("AnonymousSingh-007/phishbyte")
        >>> verdict = engine.analyze(raw_email_string)
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
        self.input_dim     = input_dim
        self.hidden_dim    = hidden_dim

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

    def forward(self, x):
        return self.net(x)

    def predict_proba(self, x):
        self.eval()
        with torch.no_grad():
            if x.dim() == 1:
                x = x.unsqueeze(0)
            return self.forward(x).item()


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