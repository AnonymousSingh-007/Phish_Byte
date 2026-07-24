"""
phishbyte/extractors/tfidf_features.py
Vocabulary-learned TF-IDF features — trained once on corpus, saved alongside weights.

Computes top-N most discriminative unigrams from training data,
then returns binary presence + TF score for each in new emails.
Zero pretrained models. Zero external embeddings. Purely from your data.

Usage in training:
    vocab = TFIDFVocab.fit(raw_emails, labels, top_n=50)
    vocab.save("phishbyte/model/weights/tfidf_vocab.json")
    features = vocab.transform(raw_email)  # returns dict of 50 float features

Usage in inference:
    vocab = TFIDFVocab.load("phishbyte/model/weights/tfidf_vocab.json")
    features = vocab.transform(raw_email)
"""

import re, json, math
from pathlib import Path
from collections import Counter
from typing import Dict, List, Tuple, Optional


_TOKEN_RE = re.compile(r'\b[a-z]{3,20}\b')
_STOPWORDS = {
    "the","and","for","are","but","not","you","all","can","had","her","was",
    "one","our","out","day","get","has","him","his","how","its","let","may",
    "new","now","own","say","she","too","use","way","who","why","with","that",
    "this","from","they","have","will","your","what","said","each","been",
    "were","when","more","also","than","into","only","over","then","there",
    "these","would","other","about","which","their","after","where","those",
    "should","through","before","between","during","without","because",
}


def _tokenize(text: str) -> List[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


class TFIDFVocab:
    """
    Lightweight TF-IDF vocabulary fitted on your own training corpus.
    Saves as a JSON file next to model weights.
    """

    def __init__(self, vocab: List[str], idf: Dict[str, float]):
        self.vocab    = vocab          # ordered list of top-N terms
        self.idf      = idf            # term → IDF score
        self.vocab_set = set(vocab)

    @classmethod
    def fit(
        cls,
        raw_emails: List[str],
        labels:     List[int],
        top_n:      int = 50,
    ) -> "TFIDFVocab":
        """
        Fit vocabulary on training corpus.
        Selects top_n terms ranked by absolute difference in
        (mean TF in phishing) vs (mean TF in legitimate).
        This is a fast, interpretable feature selection that avoids
        chi-squared or mutual information overhead.
        """
        n_docs = len(raw_emails)
        df: Dict[str, int] = Counter()          # doc frequency
        phish_tf: Dict[str, float] = Counter()  # total TF in phishing
        legit_tf: Dict[str, float] = Counter()  # total TF in legit

        n_phish = sum(labels)
        n_legit = n_docs - n_phish

        for raw, label in zip(raw_emails, labels):
            tokens = _tokenize(raw)
            if not tokens:
                continue
            tf = Counter(tokens)
            n_tok = len(tokens)
            seen = set()
            for tok, cnt in tf.items():
                if tok not in seen:
                    df[tok] += 1
                    seen.add(tok)
                score = cnt / n_tok
                if label == 1:
                    phish_tf[tok] += score
                else:
                    legit_tf[tok] += score

        # Compute IDF
        idf = {
            tok: math.log((n_docs + 1) / (freq + 1)) + 1
            for tok, freq in df.items()
        }

        # Discriminative score = |phish_mean - legit_mean| × IDF
        scores: Dict[str, float] = {}
        all_terms = set(phish_tf) | set(legit_tf)
        for tok in all_terms:
            if df.get(tok, 0) < 5:       # must appear in ≥5 docs
                continue
            pm = phish_tf.get(tok, 0) / max(n_phish, 1)
            lm = legit_tf.get(tok, 0)  / max(n_legit, 1)
            scores[tok] = abs(pm - lm) * idf.get(tok, 1.0)

        # Select top_n
        top = sorted(scores, key=lambda t: -scores[t])[:top_n]
        vocab_idf = {t: round(idf.get(t, 1.0), 6) for t in top}
        print(f"  TF-IDF vocab fitted: {len(top)} terms")
        print(f"  Top 10: {top[:10]}")
        return cls(vocab=top, idf=vocab_idf)

    def transform(self, raw_email: str) -> Dict[str, float]:
        """
        Returns a dict of TF-IDF scores for each vocab term.
        Key format: 'tfidf_{term}'  — value in [0, 1] range (clipped).
        """
        tokens = _tokenize(raw_email)
        if not tokens:
            return {f"tfidf_{t}": 0.0 for t in self.vocab}
        n = len(tokens)
        tf = Counter(tokens)
        return {
            f"tfidf_{t}": round(
                min(1.0, (tf.get(t, 0) / n) * self.idf.get(t, 1.0) * 10),
                4
            )
            for t in self.vocab
        }

    def feature_names(self) -> List[str]:
        return [f"tfidf_{t}" for t in self.vocab]

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"vocab": self.vocab, "idf": self.idf}, f, indent=2)
        print(f"  TF-IDF vocab saved → {path}")

    @classmethod
    def load(cls, path: str) -> "TFIDFVocab":
        with open(path) as f:
            data = json.load(f)
        return cls(vocab=data["vocab"], idf=data["idf"])

    @classmethod
    def load_or_none(cls, path: str) -> Optional["TFIDFVocab"]:
        try:
            return cls.load(path)
        except Exception:
            return None