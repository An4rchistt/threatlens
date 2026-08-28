"""Local curated reputation engine.

Runs *before* the sandbox scraper to give an instant, high-confidence verdict on
domains we already know about:

* **Blocklist hit** -> known-bad. Produces a CRITICAL reputation factor and a
  score that the fusion layer floors near the top of the range, so a known
  phishing/malware/scam domain is caught in milliseconds without spending a
  browser, an LLM call or an external reputation lookup.
* **Pattern hit** -> the host matches a known phishing/scam *morphology*
  (e.g. ``paypal-secure-login``); high but not absolute confidence, because a
  regex can over-match. This is where detection generalises to unseen domains.
* **Allowlist hit** -> a widely-trusted brand. Produces an informational factor
  and signals fusion to damp the final score so the live engines cannot
  false-positive a major site. NOT an absolute pass: a compromised allowlisted
  host can still be flagged by the scraper/AI.

Design constraints mirrored from the rest of the backend:
* Never raises. Any load/lookup problem degrades to ``status != "ok"``.
* Keyed on the same ``registrable_domain`` / ``hostname_of`` helpers the other
  engines use, so matching is consistent with the heuristic and intel layers.
* Data is loaded once at import from JSON files under ``backend/data`` (override
  with ``REPUTATION_FEED_PATH`` / ``REPUTATION_ALLOWLIST_PATH``).
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Set, Tuple

from models import (
    FactorSource,
    ReputationReport,
    RiskFactor,
    Severity,
    hostname_of,
    registrable_domain,
)

LOGGER = logging.getLogger("threatlens.reputation")

_TRUTHY = {"1", "true", "yes", "on", "y"}
_HERE = Path(__file__).resolve().parent
_DATA_DIR = _HERE / "data"


def _env_flag(name: str, default: str = "1") -> bool:
    return os.getenv(name, default).strip().lower() in _TRUTHY


REPUTATION_ENABLED = _env_flag("REPUTATION_ENABLED", "1")
FEED_PATH = Path(os.getenv("REPUTATION_FEED_PATH", str(_DATA_DIR / "threat_feed.json")))
ALLOWLIST_PATH = Path(
    os.getenv("REPUTATION_ALLOWLIST_PATH", str(_DATA_DIR / "allowlist.json"))
)

#: Category -> human label used in factor titles.
_CATEGORY_LABEL: Dict[str, str] = {
    "phishing": "phishing",
    "malware": "malware distribution",
    "scam": "fraud/scam",
    "abused_infra": "abused infrastructure",
}


@dataclass
class _CompiledPattern:
    id: str
    regex: Pattern[str]
    category: str
    note: str


@dataclass
class _Feed:
    """In-memory, indexed view of the curated data files."""

    blocked_domains: Dict[str, dict] = field(default_factory=dict)
    blocked_hosts: Dict[str, dict] = field(default_factory=dict)
    patterns: List[_CompiledPattern] = field(default_factory=list)
    allowed_domains: Set[str] = field(default_factory=set)
    feed_error: Optional[str] = None
    allowlist_error: Optional[str] = None

    @property
    def blocklist_size(self) -> int:
        return len(self.blocked_domains) + len(self.blocked_hosts) + len(self.patterns)

    @property
    def allowlist_size(self) -> int:
        return len(self.allowed_domains)

    @property
    def loaded(self) -> bool:
        return self.blocklist_size > 0 or self.allowlist_size > 0


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}: expected a JSON object at the top level")
    return data


def _build_feed() -> _Feed:
    feed = _Feed()

    # --- threat feed -------------------------------------------------------
    try:
        raw = _load_json(FEED_PATH)
        for entry in raw.get("domains", []) or []:
            domain = str(entry.get("domain", "")).strip().lower().strip(".")
            if domain:
                feed.blocked_domains[domain] = {
                    "category": str(entry.get("category", "phishing")),
                    "note": str(entry.get("note", "")),
                }
        for entry in raw.get("hosts", []) or []:
            host = str(entry.get("host", "")).strip().lower().strip(".")
            if host:
                feed.blocked_hosts[host] = {
                    "category": str(entry.get("category", "phishing")),
                    "note": str(entry.get("note", "")),
                }
        for entry in raw.get("patterns", []) or []:
            pattern_src = str(entry.get("regex", "")).strip()
            if not pattern_src:
                continue
            try:
                compiled = re.compile(pattern_src, re.IGNORECASE)
            except re.error as exc:
                LOGGER.warning("Skipping invalid reputation pattern %r: %s", entry.get("id"), exc)
                continue
            feed.patterns.append(
                _CompiledPattern(
                    id=str(entry.get("id", "pattern")),
                    regex=compiled,
                    category=str(entry.get("category", "phishing")),
                    note=str(entry.get("note", "")),
                )
            )
    except FileNotFoundError:
        feed.feed_error = f"threat feed not found at {FEED_PATH}"
        LOGGER.warning(feed.feed_error)
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        feed.feed_error = f"could not load threat feed: {exc}"
        LOGGER.error(feed.feed_error)

    # --- allowlist ---------------------------------------------------------
    try:
        raw = _load_json(ALLOWLIST_PATH)
        for domain in raw.get("domains", []) or []:
            cleaned = str(domain).strip().lower().strip(".")
            if cleaned:
                feed.allowed_domains.add(cleaned)
    except FileNotFoundError:
        feed.allowlist_error = f"allowlist not found at {ALLOWLIST_PATH}"
        LOGGER.warning(feed.allowlist_error)
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        feed.allowlist_error = f"could not load allowlist: {exc}"
        LOGGER.error(feed.allowlist_error)

    LOGGER.info(
        "Reputation feed loaded: %s blocked domains, %s blocked hosts, %s patterns, "
        "%s allowlisted domains.",
        len(feed.blocked_domains),
        len(feed.blocked_hosts),
        len(feed.patterns),
        len(feed.allowed_domains),
    )
    return feed


# Loaded once at import; a restart picks up refreshed files.
_FEED: _Feed = _build_feed()


def reputation_enabled() -> bool:
    return REPUTATION_ENABLED and _FEED.loaded


def blocklist_size() -> int:
    return _FEED.blocklist_size


def allowlist_size() -> int:
    return _FEED.allowlist_size


def _factor(
    factor_id: str,
    title: str,
    description: str,
    *,
    severity: Severity,
    weight: float,
    category: str,
    confidence: float,
    evidence: Optional[str] = None,
) -> RiskFactor:
    return RiskFactor(
        id=factor_id,
        title=title,
        description=description,
        category=category,
        severity=severity,
        source=FactorSource.REPUTATION,
        confidence=confidence,
        weight=weight,
        evidence=evidence,
    )


@dataclass
class ReputationResult:
    """Return bundle: a score, factors, the report model, and a fusion hint."""

    score: int
    factors: List[RiskFactor]
    report: ReputationReport
    #: "malicious" | "trusted" | "unknown" - drives the fusion floor/damper.
    classification: str


def _unknown(domain: str, status: str, detail: Optional[str]) -> ReputationResult:
    return ReputationResult(
        score=0,
        factors=[],
        report=ReputationReport(
            available=status == "ok",
            status=status,
            detail=detail,
            classification="unknown",
            checked_domain=domain,
        ),
        classification="unknown",
    )


def check_reputation(url_or_host: str) -> ReputationResult:
    """Classify a target against the local blocklist/allowlist.

    Accepts a URL or a bare host. Never raises. Order of precedence:
    exact host block > exact domain block > pattern block > allowlist.
    Blocklist always wins over allowlist so an abused subdomain of an
    allowlisted parent is still caught.
    """

    if not REPUTATION_ENABLED:
        return _unknown("", "disabled", "REPUTATION_ENABLED is off.")
    if not _FEED.loaded:
        detail = _FEED.feed_error or _FEED.allowlist_error or "no reputation data loaded"
        return _unknown("", "unavailable", detail)

    host = hostname_of(url_or_host) or (url_or_host or "").strip().lower().strip(".")
    if not host:
        return _unknown("", "skipped", "No host to classify.")
    base_domain = registrable_domain(host) or host

    # --- 1. Exact host on the blocklist -----------------------------------
    host_hit = _FEED.blocked_hosts.get(host)
    if host_hit:
        return _malicious_result(host, base_domain, host, "exact_host", host_hit)

    # --- 2. Exact registrable domain on the blocklist ---------------------
    domain_hit = _FEED.blocked_domains.get(base_domain)
    if domain_hit:
        return _malicious_result(host, base_domain, base_domain, "exact_domain", domain_hit)

    # --- 3. Morphology pattern match --------------------------------------
    #: Match against both the full host and the registrable label so a pattern
    #: keyed on "paypal-secure-login" fires whether it is the domain or a sub.
    haystack = f"{host} {base_domain}"
    for pattern in _FEED.patterns:
        if pattern.regex.search(haystack):
            return _pattern_result(host, base_domain, pattern)

    # --- 4. Allowlist ------------------------------------------------------
    if base_domain in _FEED.allowed_domains or host in _FEED.allowed_domains:
        factor = _factor(
            "reputation_trusted",
            "Domain on the trusted allowlist",
            f"'{base_domain}' is a widely-trusted, curated domain. The final score is "
            "damped so the live engines cannot false-positive a major brand; a "
            "compromised host on this domain can still be flagged by the scraper or "
            "AI analyst.",
            severity=Severity.INFO,
            weight=0.0,
            category="reputation",
            confidence=0.9,
            evidence=f"allowlist match: {base_domain}",
        )
        return ReputationResult(
            score=0,
            factors=[factor],
            report=ReputationReport(
                available=True,
                status="ok",
                classification="trusted",
                matched_value=base_domain,
                match_type="allowlist",
                category="trusted",
                source="allowlist",
                checked_domain=base_domain,
            ),
            classification="trusted",
        )

    # --- 5. Unknown: reputation had nothing, defer to the live engines ----
    return _unknown(base_domain, "ok", "No local reputation match; deferring to live analysis.")


def _malicious_result(
    host: str,
    base_domain: str,
    matched: str,
    match_type: str,
    hit: dict,
) -> ReputationResult:
    category = hit.get("category", "phishing")
    label = _CATEGORY_LABEL.get(category, category)
    note = hit.get("note", "")
    factor = _factor(
        "known_malicious_domain",
        f"Domain on the {label} blocklist",
        f"'{matched}' is on the curated {label} blocklist"
        + (f": {note}." if note else ".")
        + " This is a confirmed known-bad indicator, matched before any page was fetched.",
        severity=Severity.CRITICAL,
        weight=40.0,
        category="reputation",
        confidence=0.97,
        evidence=f"{match_type} match: {matched}",
    )
    return ReputationResult(
        score=95,
        factors=[factor],
        report=ReputationReport(
            available=True,
            status="ok",
            classification="malicious",
            matched_value=matched,
            match_type=match_type,
            category=category,
            source="threat_feed",
            checked_domain=base_domain,
        ),
        classification="malicious",
    )


def _pattern_result(host: str, base_domain: str, pattern: _CompiledPattern) -> ReputationResult:
    category = pattern.category
    label = _CATEGORY_LABEL.get(category, category)
    factor = _factor(
        "reputation_pattern_match",
        f"Host matches a known {label} pattern",
        f"The host '{host}' matches the '{pattern.id}' {label} morphology"
        + (f" ({pattern.note})" if pattern.note else "")
        + ". This structure is strongly associated with malicious domains, though a "
        "pattern match alone is slightly less certain than an exact blocklist entry.",
        severity=Severity.HIGH,
        weight=30.0,
        category="reputation",
        confidence=0.82,
        evidence=f"pattern '{pattern.id}' on {host}",
    )
    return ReputationResult(
        # High but below the exact-match floor: patterns can over-match, so leave
        # room for the live engines to corroborate or temper.
        score=78,
        factors=[factor],
        report=ReputationReport(
            available=True,
            status="ok",
            classification="malicious",
            matched_value=pattern.id,
            match_type="pattern",
            category=category,
            source="threat_feed",
            checked_domain=base_domain,
        ),
        classification="malicious",
    )


def reputation_status_detail() -> str:
    """Human summary for health/config logging."""

    if not REPUTATION_ENABLED:
        return "disabled (REPUTATION_ENABLED=0)"
    if not _FEED.loaded:
        return _FEED.feed_error or _FEED.allowlist_error or "no data loaded"
    return (
        f"{_FEED.blocklist_size} blocklist indicators, "
        f"{_FEED.allowlist_size} allowlisted domains"
    )
