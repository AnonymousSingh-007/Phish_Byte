"""
phishbyte/extractors/tfidf_features.py — v2
Fix: expanded stopwords block 'com','www','http','https' and MIME tokens.
Fix: 80% document frequency ceiling drops universal tokens.
"""
import re, json, math
from collections import Counter
from typing import Dict, List, Optional

_TOKEN_RE = re.compile(r'\b[a-z]{3,20}\b')
_STOPWORDS = {
    "the","and","for","are","but","not","you","all","can","had","her","was",
    "one","our","out","day","get","has","him","his","how","its","let","may",
    "new","now","own","say","she","too","use","way","who","why","with","that",
    "this","from","they","have","will","your","what","said","each","been",
    "were","when","more","also","than","into","only","over","then","there",
    "these","would","other","about","which","their","after","where","those",
    "should","through","before","between","during","without","because",
    # Internet/email structural tokens — KEY FIX
    "com","net","org","www","http","https","html","mailto",
    "email","mail","message","subject","reply","sender","content",
    "type","text","plain","charset","utf","mime","boundary",
    "encoded","base64","quoted","printable","transfer","encoding",
    # Short common words
    "per","via","due","ago","set","put","run","see","try","ask",
    "got","did","big","old","any","few","far","yet","nor","off",
}

def _tokenize(text):
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]

class TFIDFVocab:
    def __init__(self, vocab, idf):
        self.vocab=vocab; self.idf=idf; self.vocab_set=set(vocab)

    @classmethod
    def fit(cls, raw_emails, labels, top_n=50):
        n_docs  = len(raw_emails)
        df      = Counter()
        phish_tf= Counter()
        legit_tf= Counter()
        n_phish = sum(labels); n_legit = n_docs-n_phish
        for raw, label in zip(raw_emails, labels):
            tokens = _tokenize(raw)
            if not tokens: continue
            tf = Counter(tokens); n_tok=len(tokens); seen=set()
            for tok, cnt in tf.items():
                if tok not in seen: df[tok]+=1; seen.add(tok)
                score = cnt/n_tok
                if label==1: phish_tf[tok]+=score
                else:        legit_tf[tok]+=score
        idf = {tok: math.log((n_docs+1)/(freq+1))+1 for tok,freq in df.items()}
        scores = {}
        for tok in set(phish_tf)|set(legit_tf):
            if df.get(tok,0) < 5: continue
            if df.get(tok,0)/n_docs > 0.80: continue  # universal tokens
            pm = phish_tf.get(tok,0)/max(n_phish,1)
            lm = legit_tf.get(tok,0)/max(n_legit,1)
            scores[tok] = abs(pm-lm)*idf.get(tok,1.0)
        top = sorted(scores, key=lambda t:-scores[t])[:top_n]
        vocab_idf = {t:round(idf.get(t,1.0),6) for t in top}
        print(f"  TF-IDF vocab fitted: {len(top)} terms")
        print(f"  Top 10: {top[:10]}")
        return cls(vocab=top, idf=vocab_idf)

    def transform(self, raw_email):
        tokens=_tokenize(raw_email)
        if not tokens: return {f"tfidf_{t}":0.0 for t in self.vocab}
        n=len(tokens); tf=Counter(tokens)
        return {f"tfidf_{t}":round(min(1.0,(tf.get(t,0)/n)*self.idf.get(t,1.0)*10),4) for t in self.vocab}

    def feature_names(self): return [f"tfidf_{t}" for t in self.vocab]

    def save(self, path):
        with open(path,"w") as f: json.dump({"vocab":self.vocab,"idf":self.idf},f,indent=2)
        print(f"  TF-IDF vocab saved → {path}")

    @classmethod
    def load(cls, path):
        with open(path) as f: data=json.load(f)
        return cls(vocab=data["vocab"],idf=data["idf"])

    @classmethod
    def load_or_none(cls, path):
        try: return cls.load(path)
        except: return None