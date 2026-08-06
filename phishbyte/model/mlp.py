"""
phishbyte/model/mlp.py — v9

Changes from v8:
  - Input dim: 104 → 107 (added dmarc_pass, dkim_aligned, auth_alignment_score)
  - Architecture: 107→620→310(×2 ResBlock)→155→76→1
  - Parameters: 716,322 → 718,410
  - Everything else identical to v8
"""

import torch
import torch.nn as nn
from typing import Dict, List
from huggingface_hub import PyTorchModelHubMixin


_STATIC_FEATURES: List[str] = [
    # Domain (7)
    "domain_mismatch","replyto_differs","returnpath_differs",
    "from_is_freemail","brand_impersonation",
    "display_name_mismatch","suspicious_domain_pattern",
    # URL (5)
    "http_ratio","anchor_mismatch_score","suspicious_tld_score",
    "urgency_score","link_density_score",
    # SPF original (3) — backward compatible names
    "spf_fail","no_spf_record","no_sending_ip",
    # SPF extended — auth alignment (3 NEW)
    "dmarc_pass","dkim_aligned","auth_alignment_score",
    # Subject (7)
    "subject_urgency","subject_security","subject_brand_name",
    "subject_currency","subject_all_caps","subject_fake_re","subject_fake_txn_id",
    # Char-level (5)
    "caps_ratio","digit_ratio","special_density","avg_word_length","html_text_ratio",
    # BDI extended (5)
    "mcld_mismatch","form_action_mismatch","external_link_ratio",
    "form_action_is_ip","redirect_param_present",
    # Lexical — sender domain (6)
    "sender_digit_run_score","sender_hyphen_run_score","sender_entropy_score",
    "sender_vowel_ratio_anomaly","sender_brand_typosquat_score","sender_domain_length_score",
    # Lexical — most common link domain (6)
    "mcld_digit_run_score","mcld_hyphen_run_score","mcld_entropy_score",
    "mcld_vowel_ratio_anomaly","mcld_brand_typosquat_score","mcld_domain_length_score",
    # Cross-signal (5)
    "trust_consistency_score","spf_pass_url_discount","multi_signal_phish_score",
    "domain_bdi_agreement","lexical_brand_confusion",
    # Composite scores (5)
    "domain_layer_score","url_layer_score","spf_layer_score",
    "subject_layer_score","bdi_layer_score",
]

INPUT_DIM_STATIC = len(_STATIC_FEATURES)   # 57
TFIDF_N          = 50
INPUT_DIM        = INPUT_DIM_STATIC + TFIDF_N  # 107

HIDDEN_1, HIDDEN_2, HIDDEN_3, HIDDEN_4 = 620, 310, 155, 76


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
    tags=["phishing-detection","email-security","pytorch","from-scratch",
          "no-pretrained-weights","cascading-inference","explainable-ai",
          "cybersecurity","nlp","phishing","cross-signal-fusion",
          "lexical-analysis","calibrated-probabilities","dmarc-alignment"],
):
    """
    PhishByte MLP v9 — 107-feature, ~718K parameter email phishing classifier.

    Architecture: 107 → 620 → 310 (×2 ResBlock) → 155 → 76 → 1
    Temperature-scaled sigmoid for calibrated probability output.

    New in v9 vs v8:
      - DMARC pass/fail parsed from Authentication-Results header
      - DKIM alignment: signing domain root matches From root domain
      - auth_alignment_score: composite SPF+DKIM+DMARC trust signal
      - cross_signal trust_consistency now anchored to DMARC not raw SPF
      - Fixes false positives on ESP-relayed legitimate email (Google/ACM/LinkedIn)
    """

    def __init__(
        self,
        input_dim: int   = INPUT_DIM,
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

        self.stream = nn.Sequential(
            nn.Linear(input_dim, hidden_1), nn.BatchNorm1d(hidden_1),
            nn.ReLU(), nn.Dropout(dropout1),
            nn.Linear(hidden_1, hidden_2), nn.BatchNorm1d(hidden_2),
            nn.ReLU(), nn.Dropout(dropout2),
        )
        self.res1 = ResidualBlock(hidden_2, dropout2)
        self.res2 = ResidualBlock(hidden_2, dropout3)

        self.proj = nn.Sequential(
            nn.Linear(hidden_2, hidden_3), nn.BatchNorm1d(hidden_3),
            nn.ReLU(), nn.Dropout(dropout3),
            nn.Linear(hidden_3, hidden_4), nn.BatchNorm1d(hidden_4),
        )
        self.skip = nn.Sequential(
            nn.Linear(input_dim, hidden_4), nn.BatchNorm1d(hidden_4),
        )

        self.head = nn.Sequential(
            nn.ReLU(), nn.Dropout(0.05),
            nn.Linear(hidden_4, 1),
        )

        # Learned temperature — calibrated post-training via LBFGS
        self.temperature = nn.Parameter(torch.ones(1))

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, nonlinearity="relu")
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward_logits(self, x: torch.Tensor) -> torch.Tensor:
        """Raw logit — use with BCEWithLogitsLoss during training."""
        main = self.proj(self.res2(self.res1(self.stream(x))))
        return self.head(main + self.skip(x))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Temperature-calibrated probability — use at inference."""
        return torch.sigmoid(self.forward_logits(x) / self.temperature.clamp(min=0.05))

    def predict_proba(self, x: torch.Tensor) -> float:
        self.eval()
        with torch.no_grad():
            if x.dim() == 1:
                x = x.unsqueeze(0)
            return self.forward(x).item()

    def get_config(self) -> Dict:
        return {
            "model_type":      "PhishByteMLP",
            "version":         "9.0",
            "input_dim":       self.input_dim,
            "hidden_dims":     [HIDDEN_1, HIDDEN_2, HIDDEN_3, HIDDEN_4],
            "residual_blocks": 2,
            "static_features": INPUT_DIM_STATIC,
            "tfidf_features":  TFIDF_N,
            "temperature_scaling": True,
            "output":          "Calibrated P(phish) sigmoid scalar",
            "framework":       "pytorch",
        }


def build_feature_vector(
    d_res:          Dict,
    u_res:          Dict,
    s_res:          Dict,
    sub_res:        Dict,
    bdi_res:        Dict,
    cross_res:      Dict,
    sender_lexical: Dict,
    mcld_lexical:   Dict,
    tfidf_features: Dict[str, float],
) -> torch.Tensor:
    """
    Assemble 107-dimensional feature vector.
    Order: 57 static features + 50 TF-IDF.
    """
    d, u, s, sub, bdi, cross = (
        d_res["features"], u_res["features"], s_res["features"],
        sub_res["features"], bdi_res["features"], cross_res["features"],
    )

    static = [
        # Domain (7)
        d["domain_mismatch"], d["replyto_differs"], d["returnpath_differs"],
        d["from_is_freemail"], d["brand_impersonation"],
        d["display_name_mismatch"], d["suspicious_domain_pattern"],
        # URL (5)
        u["http_ratio"], u["anchor_mismatch_score"], u["suspicious_tld_score"],
        u["urgency_score"], u["link_density_score"],
        # SPF original (3)
        s["spf_fail"], s["no_spf_record"], s["no_sending_ip"],
        # SPF extended — auth alignment (3 NEW)
        s["dmarc_pass"], s["dkim_aligned"], s["auth_alignment_score"],
        # Subject (7)
        sub["subject_urgency"], sub["subject_security"], sub["subject_brand_name"],
        sub["subject_currency"], sub["subject_all_caps"],
        sub["subject_fake_re"], sub["subject_fake_txn_id"],
        # Char-level (5)
        u["caps_ratio"], u["digit_ratio"], u["special_density"],
        u["avg_word_length"], u["html_text_ratio"],
        # BDI extended (5)
        bdi["mcld_mismatch"], bdi["form_action_mismatch"], bdi["external_link_ratio"],
        bdi["form_action_is_ip"], bdi["redirect_param_present"],
        # Lexical — sender domain (6)
        sender_lexical["digit_run_score"], sender_lexical["hyphen_run_score"],
        sender_lexical["entropy_score"], sender_lexical["vowel_ratio_anomaly"],
        sender_lexical["brand_typosquat_score"], sender_lexical["domain_length_score"],
        # Lexical — most common link domain (6)
        mcld_lexical["digit_run_score"], mcld_lexical["hyphen_run_score"],
        mcld_lexical["entropy_score"], mcld_lexical["vowel_ratio_anomaly"],
        mcld_lexical["brand_typosquat_score"], mcld_lexical["domain_length_score"],
        # Cross-signal (5)
        cross["trust_consistency_score"], cross["spf_pass_url_discount"],
        cross["multi_signal_phish_score"], cross["domain_bdi_agreement"],
        cross["lexical_brand_confusion"],
        # Composite scores (5)
        d_res["score"], u_res["score"], s_res["score"],
        sub_res["score"], bdi_res["score"],
    ]

    tfidf_vals = list(tfidf_features.values())
    return torch.tensor(static + tfidf_vals, dtype=torch.float32)


# Backward compatibility alias
FEATURE_NAMES = _STATIC_FEATURES