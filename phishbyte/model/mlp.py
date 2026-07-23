"""
phishbyte/model/mlp.py — v6
31 features (added display_name_mismatch + suspicious_domain_pattern)
Training loop now reports F1 at optimal threshold, not naive 0.5
Architecture unchanged: 29→192→96→48→1 with residual (now 31→192→96→48→1)
"""

import torch
import torch.nn as nn
from typing import Dict, List
from huggingface_hub import PyTorchModelHubMixin


FEATURE_NAMES: List[str] = [
    # Domain (7) — was 5, added 2
    "domain_mismatch", "replyto_differs", "returnpath_differs",
    "from_is_freemail", "brand_impersonation",
    "display_name_mismatch",       # NEW
    "suspicious_domain_pattern",   # NEW
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
    # Composite (4)
    "domain_layer_score","url_layer_score","spf_layer_score","subject_layer_score",
]

INPUT_DIM  = len(FEATURE_NAMES)  # 31
HIDDEN_1   = 192
HIDDEN_2   = 96
HIDDEN_3   = 48


class ResidualBlock(nn.Module):
    def __init__(self, dim:int, dropout:float=0.2):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(dim,dim), nn.BatchNorm1d(dim), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(dim,dim), nn.BatchNorm1d(dim),
        )
        self.relu = nn.ReLU()
    def forward(self,x): return self.relu(self.block(x)+x)


class PhishByteMLPLayer(
    nn.Module,
    PyTorchModelHubMixin,
    library_name="phishbyte",
    repo_url="https://github.com/AnonymousSingh-007/Phish_Byte",
    pipeline_tag="text-classification",
    license="mit",
    tags=["phishing-detection","email-security","pytorch","from-scratch",
          "no-pretrained-weights","cascading-inference","lightweight",
          "explainable-ai","cybersecurity","nlp","phishing"],
):
    """
    PhishByte MLP v6 — 31-feature email phishing classifier.
    Architecture: 31 → 192 → ResBlock(96) → 48 → 1 (sigmoid + residual skip)
    ~53K parameters
    """
    def __init__(self, input_dim=INPUT_DIM, hidden_1=HIDDEN_1,
                 hidden_2=HIDDEN_2, hidden_3=HIDDEN_3,
                 dropout1=0.3, dropout2=0.2, dropout3=0.1):
        super().__init__()
        self.feature_names = FEATURE_NAMES
        self.input_dim     = input_dim
        self.stream = nn.Sequential(
            nn.Linear(input_dim, hidden_1), nn.BatchNorm1d(hidden_1), nn.ReLU(), nn.Dropout(dropout1),
            nn.Linear(hidden_1, hidden_2), nn.BatchNorm1d(hidden_2), nn.ReLU(), nn.Dropout(dropout2),
        )
        self.res_block  = ResidualBlock(hidden_2, dropout2)
        self.proj_main  = nn.Sequential(nn.Linear(hidden_2, hidden_3), nn.BatchNorm1d(hidden_3))
        self.skip       = nn.Sequential(nn.Linear(input_dim, hidden_3), nn.BatchNorm1d(hidden_3))
        self.head       = nn.Sequential(nn.ReLU(), nn.Dropout(dropout3), nn.Linear(hidden_3,1), nn.Sigmoid())
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m,nn.Linear):
                nn.init.kaiming_normal_(m.weight,nonlinearity="relu")
                if m.bias is not None: nn.init.zeros_(m.bias)

    def forward(self,x):
        main=self.proj_main(self.res_block(self.stream(x)))
        return self.head(main+self.skip(x))

    def predict_proba(self,x):
        self.eval()
        with torch.no_grad():
            if x.dim()==1: x=x.unsqueeze(0)
            return self.forward(x).item()

    def get_config(self):
        return {"model_type":"PhishByteMLP","version":"6.0",
                "input_dim":INPUT_DIM,"hidden_dims":[HIDDEN_1,HIDDEN_2,HIDDEN_3],
                "residual":True,"feature_names":FEATURE_NAMES,
                "output":"P(phish) sigmoid scalar","framework":"pytorch"}


def build_feature_vector(d_res, u_res, s_res, sub_res) -> torch.Tensor:
    d,u,s,sub = d_res["features"],u_res["features"],s_res["features"],sub_res["features"]
    vec = [
        d["domain_mismatch"],d["replyto_differs"],d["returnpath_differs"],
        d["from_is_freemail"],d["brand_impersonation"],
        d["display_name_mismatch"],d["suspicious_domain_pattern"],   # NEW
        u["http_ratio"],u["anchor_mismatch_score"],u["suspicious_tld_score"],
        u["urgency_score"],u["link_density_score"],
        s["spf_fail"],s["no_spf_record"],s["no_sending_ip"],
        sub["subject_urgency"],sub["subject_security"],sub["subject_brand_name"],
        sub["subject_currency"],sub["subject_all_caps"],sub["subject_fake_re"],
        sub["subject_fake_txn_id"],
        u["caps_ratio"],u["digit_ratio"],u["special_density"],
        u["avg_word_length"],u["html_text_ratio"],
        d_res["score"],u_res["score"],s_res["score"],sub_res["score"],
    ]
    return torch.tensor(vec,dtype=torch.float32)