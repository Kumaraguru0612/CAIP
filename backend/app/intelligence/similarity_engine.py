"""
Campaign Similarity Engine
===========================
Encodes each campaign's MITRE stage sequence as a TF-IDF vector and
finds the most historically similar campaigns using cosine similarity.

Searches BOTH:
  (a) Live Postgres database campaigns  — shows real-time matching
  (b) Generated reference dataset CSV   — rich coverage from day 1

This is a publishable "Campaign Intelligence" feature: instead of
treating each attack in isolation, CAIP finds pattern matches across
the historical threat corpus.
"""

import os
import csv
import math
from collections import Counter
from typing import Any


# ── Tokenisation ──────────────────────────────────────────────────────────────

def _tokenize_sequence(stages: list[str]) -> list[str]:
    """Convert stage list into n-gram tokens for TF-IDF."""
    tokens = []
    clean = [s.strip() for s in stages if s and s.strip()]
    tokens.extend(clean)
    for i in range(len(clean) - 1):
        tokens.append(f"{clean[i]}|{clean[i+1]}")
    return tokens


def _cosine(v1: dict, v2: dict) -> float:
    shared = set(v1) & set(v2)
    if not shared:
        return 0.0
    dot  = sum(v1[k] * v2[k] for k in shared)
    mag1 = math.sqrt(sum(x * x for x in v1.values()))
    mag2 = math.sqrt(sum(x * x for x in v2.values()))
    return dot / (mag1 * mag2) if mag1 and mag2 else 0.0


class SimilarityEngine:
    """
    Finds the k most similar historical campaigns to the current one.
    """

    def __init__(self, db_campaigns: list[Any] | None = None):
        """
        Parameters
        ----------
        db_campaigns : list of SQLAlchemy Campaign objects (live DB), optional
        """
        # ── Load reference dataset ─────────────────────────────────────────
        ref_path = os.path.normpath(os.path.join(
            os.path.dirname(__file__),
            "..", "..", "..", "datasets", "caip_attack_dataset.csv"
        ))
        val_path = os.path.normpath(os.path.join(
            os.path.dirname(__file__),
            "..", "..", "..", "datasets", "caip_validation_set.csv"
        ))

        self._reference: list[dict] = []

        for path in [ref_path, val_path]:
            if os.path.exists(path):
                self._reference.extend(self._load_csv_campaigns(path))

        # ── Merge live DB campaigns ────────────────────────────────────────
        if db_campaigns:
            for c in db_campaigns:
                stage_str = getattr(c, "stage", "") or ""
                stages = [s.strip() for s in stage_str.split("->") if s.strip()]
                self._reference.append({
                    "campaign_id": c.campaign_id,
                    "stages":      stages,
                    "next_stage":  None,
                    "type":        "live",
                })

        # ── Pre-build TF-IDF corpus ───────────────────────────────────────
        #   Step 1: tokenise each document
        #   Step 2: compute IDF from corpus
        #   Step 3: store per-doc TF-IDF vectors
        n = len(self._reference)
        self._corpus_tokens = [_tokenize_sequence(r["stages"]) for r in self._reference]

        # IDF from corpus (with smoothing so no term hits 0)
        df: Counter = Counter()
        for tokens in self._corpus_tokens:
            df.update(set(tokens))

        self._idf: dict[str, float] = {
            term: math.log((n + 1) / (freq + 1)) + 1.0
            for term, freq in df.items()
        }

        # Per-doc TF-IDF vectors
        self._tfidf_vectors: list[dict] = []
        for tokens in self._corpus_tokens:
            tf = Counter(tokens)
            vec = {
                term: (count / len(tokens)) * self._idf.get(term, 1.0)
                for term, count in tf.items()
            }
            self._tfidf_vectors.append(vec)

    def _query_vector(self, tokens: list[str]) -> dict:
        """Build a TF-IDF vector for a query using the pre-fitted corpus IDF."""
        if not tokens:
            return {}
        tf = Counter(tokens)
        return {
            term: (count / len(tokens)) * self._idf.get(term, 1.0)
            for term, count in tf.items()
        }

    @staticmethod
    def _load_csv_campaigns(path: str) -> list[dict]:
        """Group CSV event rows into campaign-level records."""
        campaigns: dict[str, dict] = {}
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                cid = row["campaign_id"]
                if cid not in campaigns:
                    campaigns[cid] = {
                        "campaign_id": cid,
                        "stages":      [],
                        "next_stage":  row.get("next_stage_label", ""),
                        "type":        row.get("campaign_type", "unknown"),
                    }
                stage = row.get("mitre_stage", "").strip()
                if stage and (not campaigns[cid]["stages"] or campaigns[cid]["stages"][-1] != stage):
                    campaigns[cid]["stages"].append(stage)
        return list(campaigns.values())

    def find_similar(
        self,
        current_stages: list[str],
        top_k: int = 3,
        exclude_campaign_id: str | None = None,
    ) -> list[dict]:
        """
        Parameters
        ----------
        current_stages      : ordered list of MITRE stages in current campaign
        top_k               : how many similar campaigns to return
        exclude_campaign_id : exclude the current campaign itself

        Returns
        -------
        list of dicts:
          campaign_id, similarity (0–1), predicted_next_stage, campaign_type
        """
        if not self._tfidf_vectors or not current_stages:
            return []

        query_tokens = _tokenize_sequence(current_stages)
        query_vec    = self._query_vector(query_tokens)

        scores = []
        for i, ref_vec in enumerate(self._tfidf_vectors):
            ref = self._reference[i]
            if exclude_campaign_id and ref["campaign_id"] == exclude_campaign_id:
                continue
            sim = _cosine(query_vec, ref_vec)
            if sim > 0.0:
                scores.append({
                    "campaign_id":          ref["campaign_id"],
                    "similarity":           round(sim, 4),
                    "predicted_next_stage": ref.get("next_stage") or "Unknown",
                    "campaign_type":        ref.get("type", "unknown"),
                    "historical_stages":    ref["stages"],
                })

        scores.sort(key=lambda x: x["similarity"], reverse=True)
        return scores[:top_k]
