"""Tiny text classifier: does this sentence give orders to the AI model?

TF-IDF turns each sentence into numbers (which words/word pairs it uses), and
logistic regression learns which of those numbers point to 'instruction'.
It trains in well under a second from intent_data.py, so no model file is saved.
"""
import re
from functools import lru_cache

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from .intent_data import INSTRUCTIONS, NORMAL


@lru_cache(maxsize=1)
def get_model():
    texts = INSTRUCTIONS + NORMAL
    labels = [1] * len(INSTRUCTIONS) + [0] * len(NORMAL)
    model = make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True),
        LogisticRegression(C=10, max_iter=1000, random_state=0),
    )
    return model.fit(texts, labels)


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip() for p in parts if len(p.strip()) > 3]


def instruction_probability(sentences: list[str]) -> list[float]:
    """Probability (0-1) that each sentence is a hidden instruction to the AI."""
    if not sentences:
        return []
    return list(get_model().predict_proba(sentences)[:, 1])
