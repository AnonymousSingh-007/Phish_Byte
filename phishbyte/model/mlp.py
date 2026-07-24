"""
phishbyte/model/mlp.py — v7 (250K params, 81 features)

Feature breakdown (81 total):
  Domain (7):  mismatch, replyto, returnpath, freemail, brand, display_name, susp_pattern
  URL (5):     http_ratio, anchor_mismatch, susp_tld, urgency_norm, link_density_norm
  SPF (3):     spf_fail, no_record, no_ip
  Subject (7): urgency, security, brand_name, currency, caps, fake_re, fake_txn
  Char (5):    caps_ratio, digit_ratio, special_density, avg_word_len, html_text_ratio
  BDI (3):     mcld_mismatch, form_action_mismatch, external_link_ratio   ← NEW
  Composite (4): domain, url, spf, subject layer scores
  TF-IDF (50): top-50 discriminative unigrams from training corpus         ← NEW
  BDI score (1): bdi_layer_score                                           ← NEW

Architecture: 81 → 360 → 180 (×2 ResBlock) → 90 → 48 → 1
Parameters: 252,355
"""

import torch
import torch.nn as nn
from typing import Dict, List
from huggingface_hub import PyTorchModelHubMixin

# Static features (31) — order must match build_feature_vector()
_STATIC_FEATURES: List[str] = [
    # Domain (7)
    "domain_mismatch","replyto_differs","returnpath_differs",
    "from_is_freemail","brand_impersonation",
    "display_name_mismatch","suspicious_domain_pattern",
    # URL (5)
    "http_ratio","anchor_mismatch_score","suspicious_tld_score",
    "urgency_score","link_density_score",
    # SPF (3)
    "spf_fail","no_spf_record","no_sending_ip",
    # Subject (7)
    "subject_urgency","subject_security","subject_brand_name",
    "subject_currency","subject_all_caps","subject_fake_re","subject_fake_txn_id",
    # Char-level (5)
    "caps_ratio","digit_ratio","special_density","avg_word_length","html_text_ratio",
    # BDI (3)
    "mcld_mismatch","form_action_mismatch","external_link_ratio",
    # Composite scores (4)
    "domain_layer_score","url_layer_score","spf_layer_score","subject_layer_score",
    # BDI composite (1)
    "bdi_layer_score",
]
# TF-IDF features (50) are appended dynamically at runtime
# Total = 35 static + 50 TF-IDF = 85... but we use top_n=50 so INPUT_DIM = 31+3+1+50+5 = 85
# Wait — let's count: 7+5+3+7+5+3+4+1 = 35 static + 50 tfidf = 85
# Architecture is fitted at runtime based on actual vocab size

INPUT_DIM_STATIC = len(_STATIC_FEATURES)   # 35
TFIDF_N          = 50
INPUT_DIM        = INPUT_DIM_STATIC + TFIDF_N  # 85

HIDDEN_1 = 360
HIDDEN_2 = 180
HIDDEN_3 = 90
HIDDEN_4 = 48


class ResidualBlock(nn.Module):
    def __init__(self, dim: int, dropout: float = 0.2):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim,dim), nn.BatchNorm1d(dim), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(dim,dim), nn.BatchNorm1d(dim),
        )
        self.relu = nn.ReLU()
    def forward(self, x):
        return self.relu(self.block(x) + x)


class PhishByteMLPLayer(
    nn.Module,
    PyTorchModelHubMixin,
    library_name="phishbyte",
    repo_url="https://github.com/AnonymousSingh-007/Phish_Byte",
    pipeline_tag="text-classification",
    license="mit",
    tags=[
        "phishing-detection","email-security","pytorch","from-scratch",
        "no-pretrained-weights","cascading-inference","lightweight",
        "explainable-ai","cybersecurity","nlp","phishing",
        "spam-detection","text-classification","threat-detection",
    ],
):
    """
    PhishByte MLP v7 — 85-feature, 250K parameter email phishing classifier.

    Architecture: 85 → 360 → 180 (×2 ResBlock) → 90 → 48 → 1 (sigmoid)
    - Two residual blocks at the 180-dim bottleneck for deep feature interaction
    - Skip connection from input directly to final 48-dim layer
    - ~252K parameters — lightweight vs BERT-class models at 66M+

    Feature groups:
      - 35 handcrafted rule features (domain, URL, SPF, subject, char-level, BDI)
      - 50 TF-IDF unigrams fitted on training corpus (no pretrained LM)
    """

    def __init__(
        self,
        input_dim: int   = INPUT_DIM,   # 85
        hidden_1:  int   = HIDDEN_1,
        hidden_2:  int   = HIDDEN_2,
        hidden_3:  int   = HIDDEN_3,
        hidden_4:  int   = HIDDEN_4,
        dropout1:  float = 0.3,
        dropout2:  float = 0.2,
        dropout3:  float = 0.1,
    ):
        super().__init__()
        self.input_dim = input_dim

        # Main stream: input → 360 → 180
        self.stream = nn.Sequential(
            nn.Linear(input_dim, hidden_1), nn.BatchNorm1d(hidden_1),
            nn.ReLU(), nn.Dropout(dropout1),
            nn.Linear(hidden_1, hidden_2), nn.BatchNorm1d(hidden_2),
            nn.ReLU(), nn.Dropout(dropout2),
        )
        # Two residual blocks at the 180-dim bottleneck
        self.res1 = ResidualBlock(hidden_2, dropout2)
        self.res2 = ResidualBlock(hidden_2, dropout3)

        # Projection: 180 → 90 → 48
        self.proj = nn.Sequential(
            nn.Linear(hidden_2, hidden_3), nn.BatchNorm1d(hidden_3),
            nn.ReLU(), nn.Dropout(dropout3),
            nn.Linear(hidden_3, hidden_4), nn.BatchNorm1d(hidden_4),
        )

        # Skip: input → 48 (lets gradient bypass deep stack when needed)
        self.skip = nn.Sequential(
            nn.Linear(input_dim, hidden_4), nn.BatchNorm1d(hidden_4),
        )

        # Output head
        self.head = nn.Sequential(
            nn.ReLU(), nn.Dropout(0.05),
            nn.Linear(hidden_4, 1), nn.Sigmoid(),
        )

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, nonlinearity="relu")
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        main = self.proj(self.res2(self.res1(self.stream(x))))
        return self.head(main + self.skip(x))

    def predict_proba(self, x: torch.Tensor) -> float:
        self.eval()
        with torch.no_grad():
            if x.dim() == 1: x = x.unsqueeze(0)
            return self.forward(x).item()

    def get_config(self) -> Dict:
        return {
            "model_type":   "PhishByteMLP",
            "version":      "7.0",
            "input_dim":    self.input_dim,
            "hidden_dims":  [HIDDEN_1, HIDDEN_2, HIDDEN_3, HIDDEN_4],
            "residual_blocks": 2,
            "static_features": INPUT_DIM_STATIC,
            "tfidf_features":  TFIDF_N,
            "output":       "P(phish) sigmoid scalar",
            "framework":    "pytorch",
        }


def build_feature_vector(
    d_res:   Dict,
    u_res:   Dict,
    s_res:   Dict,
    sub_res: Dict,
    bdi_res: Dict,
    tfidf_features: Dict[str, float],
) -> torch.Tensor:
    """
    Assemble 85-dimensional feature vector.
    Order: static 35 features + 50 TF-IDF features.
    """
    d, u, s, sub, bdi = (
        d_res["features"], u_res["features"],
        s_res["features"], sub_res["features"],
        bdi_res["features"],
    )

    static = [
        # Domain (7)
        d["domain_mismatch"], d["replyto_differs"], d["returnpath_differs"],
        d["from_is_freemail"], d["brand_impersonation"],
        d["display_name_mismatch"], d["suspicious_domain_pattern"],
        # URL (5)
        u["http_ratio"], u["anchor_mismatch_score"], u["suspicious_tld_score"],
        u["urgency_score"], u["link_density_score"],
        # SPF (3)
        s["spf_fail"], s["no_spf_record"], s["no_sending_ip"],
        # Subject (7)
        sub["subject_urgency"], sub["subject_security"], sub["subject_brand_name"],
        sub["subject_currency"], sub["subject_all_caps"],
        sub["subject_fake_re"], sub["subject_fake_txn_id"],
        # Char-level (5)
        u["caps_ratio"], u["digit_ratio"], u["special_density"],
        u["avg_word_length"], u["html_text_ratio"],
        # BDI (3)
        bdi["mcld_mismatch"], bdi["form_action_mismatch"], bdi["external_link_ratio"],
        # Composite (4)
        d_res["score"], u_res["score"], s_res["score"], sub_res["score"],
        # BDI composite (1)
        bdi_res["score"],
    ]

    # Append TF-IDF features in vocab order (values already 0–1 scaled)
    tfidf_vals = list(tfidf_features.values())

    return torch.tensor(static + tfidf_vals, dtype=torch.float32)