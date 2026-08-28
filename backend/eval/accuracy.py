"""Measured accuracy harness for ThreatLens.

Runs the labeled dataset (``dataset.json``) through the pre-fetch decision
layer - the local reputation engine plus the URL-shape heuristics that do NOT
require fetching a page - and reports a real confusion matrix with accuracy,
precision, recall and F1.

Why pre-fetch only: it is fully deterministic, needs no network, no browser and
no API keys, so the number is reproducible on any machine and is an honest
LOWER BOUND on the full pipeline (which additionally has the scraper + AI + live
VirusTotal to catch things this layer misses).

Usage (from backend/, with deps installed or inside the container):
    python -m eval.accuracy
    python -m eval.accuracy --threshold 40 --json

A URL is predicted "malicious" when its combined pre-fetch score >= threshold.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Allow running both as `python -m eval.accuracy` (from backend/) and directly.
_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from models import PageMetadata, hostname_of, registrable_domain  # noqa: E402
from analyzer import run_heuristics  # noqa: E402
from reputation import check_reputation  # noqa: E402

DATASET = Path(__file__).resolve().parent / "dataset.json"
DEFAULT_THRESHOLD = 40


def _prefetch_score(url: str) -> Tuple[int, str]:
    """Compute a verdict using only what is knowable before fetching the page.

    Combines the reputation engine (blocklist/allowlist/pattern) with the
    URL-shape half of the heuristic engine. Returns (score, dominant_reason).
    """

    reputation = check_reputation(url)
    if reputation.classification == "malicious":
        return reputation.score, f"reputation:{reputation.report.match_type}"
    if reputation.classification == "trusted":
        # Allowlisted: pre-fetch, treat as benign (the live engines can still
        # override on a compromised host, but that needs a fetch).
        return 0, "reputation:allowlist"

    # No reputation signal: fall back to URL-shape heuristics only. We pass an
    # empty page (no DOM) so only URL/host-derived factors contribute - exactly
    # the signal available before a fetch.
    score, factors, _ = run_heuristics(
        url=url,
        headers={},
        metadata=PageMetadata(),
        forms=[],
        links=[],
        visible_text="",
    )
    reason = factors[0].id if factors else "no_signal"
    return score, f"heuristic:{reason}"


def evaluate(threshold: int) -> Dict[str, object]:
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    samples = data.get("samples", [])

    tp = tn = fp = fn = 0
    rows: List[dict] = []
    for sample in samples:
        url = sample["url"]
        truth = sample["label"]  # "malicious" | "benign"
        score, reason = _prefetch_score(url)
        predicted = "malicious" if score >= threshold else "benign"
        correct = predicted == truth
        if truth == "malicious" and predicted == "malicious":
            tp += 1
        elif truth == "benign" and predicted == "benign":
            tn += 1
        elif truth == "benign" and predicted == "malicious":
            fp += 1
        else:
            fn += 1
        rows.append(
            {
                "url": url,
                "truth": truth,
                "predicted": predicted,
                "score": score,
                "reason": reason,
                "correct": correct,
            }
        )

    total = len(samples)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "threshold": threshold,
        "total": total,
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure ThreatLens pre-fetch accuracy.")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"Score at/above which a URL is predicted malicious (default {DEFAULT_THRESHOLD}).")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON only.")
    parser.add_argument("--errors-only", action="store_true", help="Print only misclassified rows.")
    args = parser.parse_args()

    result = evaluate(args.threshold)

    if args.json:
        result_no_rows = {k: v for k, v in result.items() if k != "rows"}
        print(json.dumps(result_no_rows, indent=2))
        return 0 if result["accuracy"] >= 0.90 else 1

    c = result["confusion"]
    print(f"\nThreatLens pre-fetch accuracy  (threshold={result['threshold']}, n={result['total']})")
    print("=" * 64)
    for row in result["rows"]:
        if args.errors_only and row["correct"]:
            continue
        mark = "OK  " if row["correct"] else "MISS"
        print(f"  {mark}  {row['truth']:9} -> {row['predicted']:9} "
              f"score={row['score']:3}  {row['reason']:28} {row['url'][:52]}")
    print("=" * 64)
    print(f"  Confusion: TP={c['tp']} TN={c['tn']} FP={c['fp']} FN={c['fn']}")
    print(f"  Accuracy : {result['accuracy'] * 100:.1f}%")
    print(f"  Precision: {result['precision'] * 100:.1f}%   (of flagged, how many were truly bad)")
    print(f"  Recall   : {result['recall'] * 100:.1f}%   (of truly bad, how many we caught)")
    print(f"  F1       : {result['f1'] * 100:.1f}%")
    verdict = "PASS (>=90%)" if result["accuracy"] >= 0.90 else "BELOW 90% TARGET"
    print(f"  Result   : {verdict}")
    print()
    return 0 if result["accuracy"] >= 0.90 else 1


if __name__ == "__main__":
    raise SystemExit(main())
