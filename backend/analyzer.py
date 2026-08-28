"""Threat analysis: LangChain LLM analyst, deterministic heuristics, VirusTotal.

Three independent opinions are produced and then fused:

1. ``run_heuristics``      - explainable, offline rules (typosquatting, credential
                             harvesting, infrastructure smells). Always runs.
2. ``analyze_with_llm``    - a LangChain ``ChatOpenAI`` chain that reads the
                             distilled page evidence and reasons about intent.
3. ``lookup_virustotal``   - reputation for the domain and the exact URL.

Fusion lives in :func:`fuse_scores`, which is a weighted blend plus hard
escalation floors so a confirmed detection can never be averaged away.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import httpx

from models import (
    AIAnalysis,
    FactorSource,
    FormSummary,
    LinkSummary,
    PageMetadata,
    RiskFactor,
    RiskLevel,
    ScoreBreakdown,
    Severity,
    VirusTotalReport,
    VirusTotalStats,
    coerce_ip_literal,
    dedupe_risk_factors,
    hostname_of,
    is_shared_hosting,
    public_suffix_of,
    registrable_domain,
    same_site,
    score_to_risk_level,
    subdomain_of,
)

LOGGER = logging.getLogger("threatlens.analyzer")

_TRUTHY = {"1", "true", "yes", "on", "y"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


# ===========================================================================
# AI provider configuration
# ===========================================================================
#
# Every supported provider speaks the OpenAI chat-completions dialect, so a
# single ``ChatOpenAI`` client covers all of them and no extra dependency is
# needed. Switching provider is purely an environment change.


@dataclass(frozen=True)
class ProviderPreset:
    """Connection defaults for one OpenAI-compatible inference provider."""

    key: str
    label: str
    base_url: str
    default_model: str
    key_env: str
    signup_url: str
    json_mode: bool = True
    requires_key: bool = True
    free_tier: str = ""


#: Ordered by auto-detection preference: the first provider with a key present
#: wins when AI_PROVIDER is not set explicitly.
PROVIDER_PRESETS: Dict[str, ProviderPreset] = {
    "groq": ProviderPreset(
        key="groq",
        label="Groq",
        base_url="https://api.groq.com/openai/v1",
        # Groq retired llama-3.3-70b-versatile / llama-3.1-8b-instant for free
        # and developer tiers in August 2026 and now points new traffic at the
        # gpt-oss family. Using a retired ID returns model_not_found.
        default_model="openai/gpt-oss-20b",
        key_env="GROQ_API_KEY",
        signup_url="https://console.groq.com/keys",
        json_mode=True,
        free_tier="Free tier, no credit card, roughly 30 requests/minute.",
    ),
    "gemini": ProviderPreset(
        key="gemini",
        label="Google Gemini",
        # Google's OpenAI-compatibility shim; the trailing slash matters.
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        # gemini-2.5-flash is still returned by ListModels but generateContent
        # rejects it for new API keys ("no longer available to new users"), so
        # the catalogue is not a safe source for this default. Google's own
        # error message points at gemini-3.6-flash. Use 'gemini-flash-latest'
        # instead if you would rather track the current flash model
        # automatically and accept that its behaviour can shift.
        default_model="gemini-3.6-flash",
        key_env="GEMINI_API_KEY",
        signup_url="https://aistudio.google.com/apikey",
        json_mode=True,
        free_tier="Free tier via AI Studio; per-model daily request caps.",
    ),
    "openrouter": ProviderPreset(
        key="openrouter",
        label="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        # OpenRouter's free catalogue rotates, so this default is a moving
        # target: verify with `GET /api/v1/models` and filter for ids ending
        # ':free'. Verified live on 2026-08-27 - scored a synthetic phishing
        # capture 98/100 and a benign page 1/100 with native JSON mode.
        # meta-llama/llama-3.3-70b-instruct:free is NOT in the free catalogue.
        default_model="minimax/minimax-m3:free",
        key_env="OPENROUTER_API_KEY",
        signup_url="https://openrouter.ai/keys",
        json_mode=True,
        free_tier="Rotating catalogue of ':free' variants; the default costs nothing.",
    ),
    "ollama": ProviderPreset(
        key="ollama",
        label="Ollama (local)",
        base_url="http://ollama:11434/v1",
        default_model="llama3.2",
        key_env="OLLAMA_API_KEY",
        signup_url="https://ollama.com/download",
        json_mode=True,
        requires_key=False,
        free_tier="Fully local and offline; no key, no quota, needs ~3GB RAM.",
    ),
    "openai": ProviderPreset(
        key="openai",
        label="OpenAI",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        key_env="OPENAI_API_KEY",
        signup_url="https://platform.openai.com/api-keys",
        json_mode=True,
        free_tier="Paid only; requires a funded balance.",
    ),
}

#: Sentinel used when the provider needs no credential (local inference).
_NO_KEY_SENTINEL = "not-required"


def _detect_provider() -> str:
    """Choose a provider from the environment.

    Explicit ``AI_PROVIDER`` always wins. Otherwise the first preset with its
    key present is used, so adding a single key is enough to switch engines.
    """

    requested = os.getenv("AI_PROVIDER", "").strip().lower()
    if requested:
        if requested in PROVIDER_PRESETS:
            return requested
        if requested == "custom" or os.getenv("AI_BASE_URL", "").strip():
            return "custom"
        LOGGER.warning(
            "Unknown AI_PROVIDER=%r; falling back to auto-detection. Known providers: %s",
            requested,
            ", ".join(PROVIDER_PRESETS),
        )

    for name, preset in PROVIDER_PRESETS.items():
        if os.getenv(preset.key_env, "").strip():
            return name
    if os.getenv("AI_API_KEY", "").strip() and os.getenv("AI_BASE_URL", "").strip():
        return "custom"
    # Nothing configured: advertise the free default so the UI can point at it.
    return "groq"


AI_PROVIDER: str = _detect_provider()

_CUSTOM_PRESET = ProviderPreset(
    key="custom",
    label=os.getenv("AI_PROVIDER_LABEL", "Custom OpenAI-compatible").strip()
    or "Custom OpenAI-compatible",
    base_url=os.getenv("AI_BASE_URL", "").strip(),
    default_model=os.getenv("AI_MODEL", "").strip() or "unset",
    key_env="AI_API_KEY",
    signup_url="",
    json_mode=os.getenv("AI_JSON_MODE", "1").strip().lower() in _TRUTHY,
    requires_key=bool(os.getenv("AI_API_KEY", "").strip()),
    free_tier="Operator supplied.",
)

AI_PRESET: ProviderPreset = PROVIDER_PRESETS.get(AI_PROVIDER, _CUSTOM_PRESET)
AI_PROVIDER_LABEL: str = AI_PRESET.label


def _resolve_api_key(preset: ProviderPreset) -> str:
    """Provider-specific key, then the generic one, then legacy OPENAI_API_KEY."""

    for name in (preset.key_env, "AI_API_KEY"):
        value = os.getenv(name, "").strip()
        if value:
            return value
    if not preset.requires_key:
        return _NO_KEY_SENTINEL
    # Back-compat: earlier builds only knew about OPENAI_API_KEY.
    if preset.key == "openai":
        return os.getenv("OPENAI_API_KEY", "").strip()
    return ""


AI_API_KEY: str = _resolve_api_key(AI_PRESET)
AI_MODEL: str = (
    os.getenv("AI_MODEL", "").strip()
    or (os.getenv("OPENAI_MODEL", "").strip() if AI_PROVIDER == "openai" else "")
    or AI_PRESET.default_model
)
AI_BASE_URL: str = (
    os.getenv("AI_BASE_URL", "").strip()
    or os.getenv("OPENAI_BASE_URL", "").strip()
    or AI_PRESET.base_url
)
AI_TIMEOUT_SECONDS: float = _env_float(
    "AI_TIMEOUT_SECONDS", _env_float("OPENAI_TIMEOUT_SECONDS", 45.0)
)
#: Deliberately generous. Reasoning models (Gemini 3.x, o-series) spend output
#: tokens thinking before emitting any content, so a tight budget yields
#: finish_reason=length with an empty message rather than a short answer.
AI_MAX_TOKENS: int = _env_int("AI_MAX_TOKENS", _env_int("OPENAI_MAX_TOKENS", 4096))
#: Optional thinking-budget lever, passed straight through when set. Valid values
#: are provider specific: Gemini accepts low/medium/high and rejects "none" with
#: HTTP 400, so this stays unset unless an operator opts in.
AI_REASONING_EFFORT: str = os.getenv("AI_REASONING_EFFORT", "").strip().lower()

#: Site identity for providers that attribute traffic to the calling app.
AI_SITE_URL: str = os.getenv("AI_SITE_URL", "http://localhost:3000").strip()
AI_SITE_NAME: str = os.getenv("AI_SITE_NAME", "ThreatLens").strip()


def ai_request_headers() -> Dict[str, str]:
    """Extra HTTP headers to send with each inference request.

    OpenRouter uses HTTP-Referer and X-Title to attribute usage to the calling
    application; they are optional but recommended, and omitting them makes the
    traffic anonymous in the dashboard.
    """

    if AI_PROVIDER != "openrouter":
        return {}
    headers: Dict[str, str] = {}
    if AI_SITE_URL:
        headers["HTTP-Referer"] = AI_SITE_URL
    if AI_SITE_NAME:
        headers["X-Title"] = AI_SITE_NAME
    return headers
AI_JSON_MODE: bool = os.getenv("AI_JSON_MODE", "").strip().lower() in _TRUTHY or (
    not os.getenv("AI_JSON_MODE", "").strip() and AI_PRESET.json_mode
)

#: Retained so existing imports and log lines keep working.
OPENAI_MODEL: str = AI_MODEL

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VIRUSTOTAL_TIMEOUT_SECONDS = _env_float("VIRUSTOTAL_TIMEOUT_SECONDS", 15.0)
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

MAX_EVIDENCE_TEXT_CHARS = _env_int("AI_EVIDENCE_TEXT_CHARS", 5000)
MAX_EVIDENCE_DOM_CHARS = _env_int("AI_EVIDENCE_DOM_CHARS", 6000)


def ai_enabled() -> bool:
    """True when the AI analyst pass has everything it needs to run."""

    if not AI_BASE_URL:
        return False
    return bool(AI_API_KEY)


def ai_provider_info() -> Dict[str, Any]:
    """Non-sensitive provider description for /api/config and health logs."""

    return {
        "provider": AI_PROVIDER,
        "label": AI_PROVIDER_LABEL,
        "model": AI_MODEL,
        "base_url": AI_BASE_URL,
        "json_mode": AI_JSON_MODE,
        "enabled": ai_enabled(),
        "key_env": AI_PRESET.key_env,
        "signup_url": AI_PRESET.signup_url,
        "free_tier": AI_PRESET.free_tier,
    }


def threat_intel_enabled() -> bool:
    return bool(VIRUSTOTAL_API_KEY)


# ===========================================================================
# Brand / typosquatting reference data
# ===========================================================================

#: Legitimate registrable domains for high-value brands. A page that *looks*
#: like one of these but is served from anywhere else is impersonation.
BRAND_DOMAINS: Dict[str, Tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "apple": ("apple.com", "icloud.com", "me.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "sharepoint.com", "msn.com"),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com", "goo.gl"),
    "amazon": ("amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.in", "amazon.de"),
    "facebook": ("facebook.com", "fb.com", "messenger.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "wa.me"),
    "netflix": ("netflix.com",),
    "linkedin": ("linkedin.com", "licdn.com"),
    "twitter": ("twitter.com", "x.com"),
    "telegram": ("telegram.org", "t.me"),
    "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "adobe": ("adobe.com", "adobelogin.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "roblox": ("roblox.com",),
    "spotify": ("spotify.com",),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com", "binance.us"),
    "metamask": ("metamask.io",),
    "kraken": ("kraken.com",),
    "blockchain": ("blockchain.com",),
    "chase": ("chase.com", "jpmorgan.com"),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com", "bofa.com"),
    "citibank": ("citi.com", "citibank.com"),
    "hsbc": ("hsbc.com", "hsbc.co.uk"),
    "barclays": ("barclays.co.uk", "barclays.com"),
    "santander": ("santander.com", "santander.co.uk"),
    "lloyds": ("lloydsbank.com",),
    "natwest": ("natwest.com",),
    "revolut": ("revolut.com",),
    "monzo": ("monzo.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "usps": ("usps.com",),
    "royalmail": ("royalmail.com",),
    "irs": ("irs.gov",),
    "hmrc": ("hmrc.gov.uk", "gov.uk"),
    "sbi": ("onlinesbi.sbi", "sbi.co.in"),
    "hdfc": ("hdfcbank.com",),
    "icici": ("icicibank.com",),
    "axis": ("axisbank.com",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "zoom": ("zoom.us", "zoom.com"),
}

#: Registrable-domain labels used for edit-distance typosquat detection.
_TYPOSQUAT_TARGETS: Tuple[str, ...] = tuple(
    sorted(
        {
            domain.split(".")[0]
            for domains in BRAND_DOMAINS.values()
            for domain in domains
            if len(domain.split(".")[0]) >= 5
        }
    )
)

#: TLDs with disproportionate abuse rates or browser-confusable names.
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club",
        "work", "click", "link", "country", "stream", "download", "review",
        "kim", "loan", "men", "gdn", "racing", "win", "bid", "rest", "cam",
        "buzz", "icu", "cyou", "sbs", "lol", "monster", "quest", "surf",
        "cfd", "bond", "autos", "boats", "best", "shop", "fit", "beauty",
        "hair", "skin", "makeup", "christmas", "mom", "wiki", "site",
        "online", "live", "life", "world", "space", "website", "press", "su",
    }
)

#: Words that appear in phishing hostnames and paths far more than in benign ones.
_URGENCY_KEYWORDS: Tuple[str, ...] = (
    "verify", "verification", "secure", "security", "update", "confirm",
    "account", "signin", "login", "logon", "auth", "authenticate", "recover",
    "recovery", "unlock", "locked", "suspend", "suspended", "billing",
    "payment", "invoice", "refund", "wallet", "webscr", "support", "helpdesk",
    "reset", "password", "credential", "validate", "restore", "alert",
    "notice", "urgent", "expire", "expired", "limited", "unusual",
)

_SOCIAL_ENGINEERING_PHRASES: Tuple[Tuple[str, str], ...] = (
    ("account will be suspended", "Suspension threat"),
    ("account has been suspended", "Suspension claim"),
    ("account has been locked", "Lockout claim"),
    ("unusual sign-in", "Fake sign-in alert"),
    ("unusual activity", "Fake activity alert"),
    ("verify your identity", "Identity verification lure"),
    ("verify your account", "Account verification lure"),
    ("confirm your identity", "Identity confirmation lure"),
    ("update your payment", "Payment update lure"),
    ("update your billing", "Billing update lure"),
    ("payment failed", "Failed payment lure"),
    ("within 24 hours", "Artificial deadline"),
    ("within 48 hours", "Artificial deadline"),
    ("immediately", "Urgency pressure"),
    ("act now", "Urgency pressure"),
    ("final warning", "Threat escalation"),
    ("your package could not be delivered", "Parcel delivery lure"),
    ("customs fee", "Customs fee lure"),
    ("tax refund", "Tax refund lure"),
    ("you have won", "Prize lure"),
    ("claim your reward", "Prize lure"),
    ("seed phrase", "Crypto wallet drain"),
    ("recovery phrase", "Crypto wallet drain"),
    ("private key", "Crypto wallet drain"),
    ("gift card", "Gift card fraud"),
)


# ===========================================================================
# Heuristic engine
# ===========================================================================


def damerau_levenshtein(left: str, right: str, max_distance: int = 3) -> int:
    """Optimal string alignment distance with early exit.

    Transpositions matter for typosquatting (``ppaypal`` / ``paypla``), so a
    plain Levenshtein implementation would under-report.
    """

    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous_previous: List[int] = []
    previous = list(range(len(right) + 1))

    for i, left_char in enumerate(left, start=1):
        current = [i] + [0] * len(right)
        row_min = current[0]
        for j, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            current[j] = min(
                current[j - 1] + 1,          # insertion
                previous[j] + 1,             # deletion
                previous[j - 1] + cost,      # substitution
            )
            if (
                i > 1
                and j > 1
                and left_char == right[j - 2]
                and left[i - 2] == right_char
            ):
                current[j] = min(current[j], previous_previous[j - 2] + cost)
            row_min = min(row_min, current[j])
        if row_min > max_distance:
            return max_distance + 1
        previous_previous = previous
        previous = current

    return previous[-1]


def _factor(
    factor_id: str,
    title: str,
    description: str,
    *,
    severity: Severity,
    weight: float,
    category: str = "general",
    confidence: float = 0.85,
    evidence: Optional[str] = None,
    source: FactorSource = FactorSource.HEURISTIC,
) -> RiskFactor:
    return RiskFactor(
        id=factor_id,
        title=title,
        description=description,
        category=category,
        severity=severity,
        source=source,
        confidence=max(0.0, min(confidence, 1.0)),
        weight=max(0.0, min(weight, 100.0)),
        evidence=(evidence or None),
    )


def _analyse_url_shape(url: str, host: str, base_domain: str) -> List[RiskFactor]:
    factors: List[RiskFactor] = []
    parsed = urlparse(url)
    path_and_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()
    scheme = (parsed.scheme or "").lower()
    subdomain = subdomain_of(host)
    tld = (public_suffix_of(host).split(".")[-1] if host else "").lower()

    if scheme != "https":
        factors.append(
            _factor(
                "no_tls",
                "Served over plain HTTP",
                "The page is not encrypted, so anything typed into it travels in "
                "clear text. Legitimate sign-in pages have used HTTPS universally for years.",
                severity=Severity.HIGH,
                weight=18,
                category="transport",
                evidence=f"scheme={scheme}",
            )
        )

    if coerce_ip_literal(host) is not None:
        factors.append(
            _factor(
                "ip_literal_host",
                "Bare IP address instead of a domain",
                "The site is reached by raw IP address. This is typical of "
                "throwaway phishing infrastructure and of compromised hosts, "
                "because no certificate or brand name is needed.",
                severity=Severity.HIGH,
                weight=22,
                category="infrastructure",
                evidence=f"host={host}",
            )
        )

    if len(url) > 120:
        factors.append(
            _factor(
                "excessive_url_length",
                "Unusually long URL",
                "Long URLs are used to push the real domain out of view in "
                "browser and mail clients.",
                severity=Severity.LOW,
                weight=6,
                category="url",
                confidence=0.6,
                evidence=f"{len(url)} characters",
            )
        )

    label_count = host.count(".") + 1
    if label_count >= 5:
        factors.append(
            _factor(
                "deep_subdomain_nesting",
                "Deeply nested subdomains",
                "Many stacked labels are used to bury the real registrable domain "
                "behind brand-looking text (e.g. login.brand.com.attacker.tld).",
                severity=Severity.MEDIUM,
                weight=12,
                category="url",
                evidence=f"host={host} ({label_count} labels)",
            )
        )

    base_label = base_domain.split(".")[0] if base_domain else ""
    hyphens = base_label.count("-")
    if hyphens >= 2:
        factors.append(
            _factor(
                "hyphenated_domain",
                "Heavily hyphenated domain",
                "Multiple hyphens in the registrable domain are a hallmark of "
                "brand-lookalike registrations such as 'secure-login-account'.",
                severity=Severity.MEDIUM,
                weight=9,
                category="url",
                confidence=0.65,
                evidence=base_domain,
            )
        )

    if re.search(r"\d{2,}", base_label) and coerce_ip_literal(host) is None:
        factors.append(
            _factor(
                "numeric_domain",
                "Digits embedded in the domain name",
                "Numeric padding is commonly used to generate large batches of "
                "disposable phishing domains.",
                severity=Severity.LOW,
                weight=5,
                category="url",
                confidence=0.55,
                evidence=base_domain,
            )
        )

    if tld in SUSPICIOUS_TLDS:
        factors.append(
            _factor(
                "high_risk_tld",
                f"High-abuse top-level domain (.{tld})",
                "This TLD is either free or extremely cheap and shows abuse rates "
                "far above the average; .zip and .mov additionally impersonate "
                "file extensions.",
                severity=Severity.MEDIUM,
                weight=11,
                category="infrastructure",
                confidence=0.7,
                evidence=f".{tld}",
            )
        )

    if "xn--" in host:
        factors.append(
            _factor(
                "punycode_homograph",
                "Punycode (IDN) host name",
                "The host uses internationalised characters, which can render as "
                "a visually identical copy of a real brand domain (homograph attack).",
                severity=Severity.HIGH,
                weight=20,
                category="impersonation",
                evidence=host,
            )
        )

    matched_keywords = sorted(
        {word for word in _URGENCY_KEYWORDS if word in f"{subdomain} {path_and_query}"}
    )
    if len(matched_keywords) >= 2:
        factors.append(
            _factor(
                "credential_bait_keywords",
                "Credential-bait wording in the URL",
                "The host or path is stuffed with security and account-recovery "
                "language to make a hostile URL look procedural.",
                severity=Severity.MEDIUM,
                weight=10,
                category="url",
                confidence=0.7,
                evidence=", ".join(matched_keywords[:8]),
            )
        )

    if re.search(r"\.(?:php|asp|aspx|cgi|pl)$", (parsed.path or "").lower()) and matched_keywords:
        factors.append(
            _factor(
                "script_endpoint_login",
                "Login flow served by a bare script endpoint",
                "Credential pages hosted directly on a .php/.asp style endpoint "
                "with security wording are typical of off-the-shelf phishing kits.",
                severity=Severity.LOW,
                weight=6,
                category="url",
                confidence=0.55,
                evidence=parsed.path[:120],
            )
        )

    if is_shared_hosting(host):
        factors.append(
            _factor(
                "free_hosting_platform",
                "Hosted on a free/shared platform",
                "The page lives on a free hosting or preview platform where anyone "
                "can publish anonymously in minutes. Brand sign-in pages never do.",
                severity=Severity.MEDIUM,
                weight=13,
                category="infrastructure",
                confidence=0.75,
                evidence=base_domain,
            )
        )

    return factors


def _analyse_brand_impersonation(
    host: str,
    base_domain: str,
    metadata: PageMetadata,
    visible_text: str,
) -> Tuple[List[RiskFactor], Optional[str]]:
    factors: List[RiskFactor] = []
    base_label = base_domain.split(".")[0] if base_domain else ""
    subdomain = subdomain_of(host)
    haystack = f"{metadata.title} {visible_text[:6000]}".lower()
    impersonated: Optional[str] = None

    # --- 1. Edit-distance typosquatting on the registrable label -----------
    if base_label and len(base_label) >= 4 and coerce_ip_literal(host) is None:
        for target in _TYPOSQUAT_TARGETS:
            if base_label == target:
                continue
            distance = damerau_levenshtein(base_label, target, max_distance=2)
            if 1 <= distance <= 2:
                impersonated = impersonated or target
                factors.append(
                    _factor(
                        "typosquatting",
                        f"Typosquatted domain resembling '{target}'",
                        f"The registrable label '{base_label}' is only {distance} edit"
                        f"{'s' if distance > 1 else ''} away from the legitimate brand "
                        f"'{target}'. This is the classic look-alike registration used "
                        "to catch mistyped and skim-read URLs.",
                        severity=Severity.CRITICAL if distance == 1 else Severity.HIGH,
                        weight=34 if distance == 1 else 26,
                        category="impersonation",
                        confidence=0.9 if distance == 1 else 0.8,
                        evidence=f"{base_label} vs {target} (distance {distance})",
                    )
                )
                break

    # --- 2. Brand name in the subdomain but not in the real domain --------
    for brand, legit_domains in BRAND_DOMAINS.items():
        if base_domain in legit_domains:
            continue
        in_subdomain = brand in subdomain.replace("-", "").replace(".", "")
        in_domain_label = brand in base_label.replace("-", "")
        if not (in_subdomain or in_domain_label):
            continue
        impersonated = impersonated or brand
        location = "subdomain" if in_subdomain else "domain label"
        factors.append(
            _factor(
                "brand_in_wrong_domain",
                f"'{brand}' branding on an unrelated domain",
                f"The {location} advertises {brand.title()}, but the registrable "
                f"domain is '{base_domain}', which is not one of that brand's real "
                f"domains ({', '.join(legit_domains[:3])}). Browsers only honour the "
                "registrable domain, so this is impersonation.",
                severity=Severity.HIGH,
                weight=28,
                category="impersonation",
                confidence=0.85,
                evidence=f"host={host}",
            )
        )
        break

    # --- 3. Page content claims a brand the domain does not own -----------
    for brand in metadata.brand_keywords:
        legit_domains = BRAND_DOMAINS.get(brand)
        if not legit_domains or base_domain in legit_domains:
            continue
        if brand not in haystack:
            continue
        if any(existing.id == "brand_in_wrong_domain" for existing in factors):
            break
        impersonated = impersonated or brand
        factors.append(
            _factor(
                "content_brand_mismatch",
                f"Page content impersonates {brand.title()}",
                f"The rendered page presents itself as {brand.title()} while being "
                f"served from '{base_domain}'. Brand content on unaffiliated "
                "infrastructure is the core definition of a phishing page.",
                severity=Severity.HIGH,
                weight=24,
                category="impersonation",
                confidence=0.75,
                evidence=f"title={metadata.title[:120] or 'n/a'}",
            )
        )
        break

    # --- 4. Homograph-style character swapping ----------------------------
    if base_label and re.search(r"(rn|vv|l1|1l|0o|o0)", base_label):
        for target in _TYPOSQUAT_TARGETS:
            normalised = (
                base_label.replace("rn", "m").replace("vv", "w").replace("1", "l").replace("0", "o")
            )
            if normalised == target and base_label != target:
                impersonated = impersonated or target
                factors.append(
                    _factor(
                        "character_substitution",
                        f"Character-swap lookalike of '{target}'",
                        "Confusable ASCII substitutions (rn->m, vv->w, 1->l, 0->o) "
                        "make the domain read as the legitimate brand at a glance.",
                        severity=Severity.CRITICAL,
                        weight=32,
                        category="impersonation",
                        confidence=0.85,
                        evidence=f"{base_label} normalises to {normalised}",
                    )
                )
                break

    return factors, impersonated


def _analyse_credential_harvesting(
    url: str,
    host: str,
    forms: Sequence[FormSummary],
    metadata: PageMetadata,
) -> List[RiskFactor]:
    factors: List[RiskFactor] = []
    is_https = url.lower().startswith("https://")

    password_forms = [form for form in forms if form.has_password_field]
    cross_origin_forms = [
        form for form in forms if form.is_cross_origin and (form.has_password_field or form.input_count >= 2)
    ]
    insecure_forms = [form for form in forms if form.action_is_insecure and form.has_password_field]

    if password_forms:
        factors.append(
            _factor(
                "credential_form_present",
                "Credential input form detected",
                f"{len(password_forms)} form(s) collect a password. On its own this is "
                "normal for a sign-in page, but it is the precondition for every "
                "credential-harvesting attack and raises the impact of every other finding.",
                severity=Severity.MEDIUM if is_https else Severity.HIGH,
                weight=12 if is_https else 20,
                category="credential_harvesting",
                confidence=0.9,
                evidence="; ".join(
                    f"action={form.resolved_action[:100] or '(self)'} method={form.method}"
                    for form in password_forms[:3]
                ),
            )
        )

    if not is_https and password_forms:
        factors.append(
            _factor(
                "password_over_http",
                "Password submitted without encryption",
                "A password field is served over plain HTTP, so credentials can be "
                "read by anyone on the network path. No legitimate service does this.",
                severity=Severity.CRITICAL,
                weight=30,
                category="credential_harvesting",
                confidence=0.95,
                evidence=url[:180],
            )
        )

    for form in cross_origin_forms[:3]:
        action_host = hostname_of(form.resolved_action)
        factors.append(
            _factor(
                "cross_origin_form_action",
                "Form posts credentials to a third-party domain",
                f"Input is submitted to '{action_host or form.resolved_action[:80]}', a "
                f"different registrable domain than the page host '{host}'. This is the "
                "exfiltration channel of a phishing kit: the victim sees one brand while "
                "the data goes somewhere else.",
                severity=Severity.CRITICAL if form.has_password_field else Severity.HIGH,
                weight=32 if form.has_password_field else 20,
                category="credential_harvesting",
                confidence=0.9,
                evidence=f"action={form.resolved_action[:180]}",
            )
        )

    for form in insecure_forms[:2]:
        factors.append(
            _factor(
                "insecure_form_action",
                "Credential form target is unencrypted",
                "The form action uses http://, downgrading the submission even if the "
                "page itself was loaded over HTTPS.",
                severity=Severity.HIGH,
                weight=22,
                category="credential_harvesting",
                confidence=0.9,
                evidence=form.resolved_action[:180],
            )
        )

    empty_action_password = [
        form for form in forms if form.has_password_field and form.action_is_empty
    ]
    if empty_action_password:
        factors.append(
            _factor(
                "form_without_action",
                "Credential form has no submit target",
                "A password form with an empty action normally relies on JavaScript to "
                "ship the data. With scripting disabled the destination is hidden, which "
                "is itself evasive behaviour.",
                severity=Severity.MEDIUM,
                weight=10,
                category="credential_harvesting",
                confidence=0.6,
                evidence=f"{len(empty_action_password)} form(s)",
            )
        )

    sensitive_names = {
        name.lower()
        for form in forms
        for name in form.input_names
        if any(hint in name.lower() for hint in ("cvv", "cvc", "card", "ssn", "seed", "mnemonic", "otp", "pin"))
    }
    if sensitive_names:
        factors.append(
            _factor(
                "high_value_data_request",
                "Requests highly sensitive data",
                "The page asks for card, one-time-code, national identifier or crypto "
                "recovery data. These fields are hallmarks of financial fraud and wallet "
                "drainer pages rather than ordinary authentication.",
                severity=Severity.CRITICAL,
                weight=28,
                category="credential_harvesting",
                confidence=0.85,
                evidence=", ".join(sorted(sensitive_names)[:10]),
            )
        )

    if metadata.hidden_input_count >= 6 and password_forms:
        factors.append(
            _factor(
                "excessive_hidden_fields",
                "Many hidden fields alongside a credential form",
                "Phishing kits carry hidden fields for campaign IDs, victim tracking and "
                "exfiltration endpoints.",
                severity=Severity.LOW,
                weight=7,
                category="credential_harvesting",
                confidence=0.6,
                evidence=f"{metadata.hidden_input_count} hidden inputs",
            )
        )

    return factors


def _analyse_page_behaviour(
    url: str,
    host: str,
    metadata: PageMetadata,
    links: Sequence[LinkSummary],
    visible_text: str,
) -> List[RiskFactor]:
    factors: List[RiskFactor] = []

    if metadata.meta_refresh:
        factors.append(
            _factor(
                "meta_refresh_redirect",
                "Automatic meta-refresh redirect",
                "The page immediately forwards the visitor elsewhere without user "
                "action, a standard cloaking technique to keep the landing URL clean "
                "for scanners.",
                severity=Severity.MEDIUM,
                weight=14,
                category="evasion",
                confidence=0.8,
                evidence=metadata.meta_refresh[:180],
            )
        )

    off_site_iframes = [
        source for source in metadata.iframe_sources if source and not same_site(url, source)
    ]
    if off_site_iframes:
        factors.append(
            _factor(
                "third_party_iframe",
                "Content framed from a third-party origin",
                "The visible page is partly or wholly loaded from another origin, which "
                "lets an attacker overlay a real site or host the credential form off-site.",
                severity=Severity.MEDIUM,
                weight=12,
                category="evasion",
                confidence=0.7,
                evidence=", ".join(source[:100] for source in off_site_iframes[:3]),
            )
        )

    if metadata.obfuscation_markers:
        interesting = [
            marker
            for marker in metadata.obfuscation_markers
            if marker
            not in {"password field present", "punycode host", "data: URI resource"}
        ]
        if interesting:
            factors.append(
                _factor(
                    "obfuscated_markup",
                    "Obfuscated or packed page source",
                    "The markup contains encoded payload patterns "
                    f"({', '.join(interesting[:5])}). Legitimate sites rarely need to hide "
                    "their own content from inspection.",
                    severity=Severity.MEDIUM,
                    weight=13,
                    category="evasion",
                    confidence=0.7,
                    evidence=", ".join(interesting[:6]),
                )
            )

    if metadata.dom_length and metadata.text_length < 220 and metadata.form_count == 0:
        factors.append(
            _factor(
                "empty_shell_page",
                "Almost no readable content",
                "With scripting disabled the page renders essentially nothing, which "
                "means the real content is assembled by script - common for cloaked "
                "landing pages and redirect gateways.",
                severity=Severity.LOW,
                weight=8,
                category="evasion",
                confidence=0.6,
                evidence=f"{metadata.text_length} visible characters",
            )
        )

    if len(metadata.redirect_chain) >= 3:
        factors.append(
            _factor(
                "long_redirect_chain",
                "Long redirect chain before landing",
                "Several hops were followed before the final page. Redirect chains are "
                "used to launder the origin and to filter out security crawlers.",
                severity=Severity.MEDIUM,
                weight=10,
                category="evasion",
                confidence=0.65,
                evidence=" -> ".join(item[:60] for item in metadata.redirect_chain[:4]),
            )
        )

    if metadata.favicon and not same_site(url, metadata.favicon) and metadata.favicon.startswith("http"):
        factors.append(
            _factor(
                "borrowed_favicon",
                "Favicon loaded from another domain",
                "The tab icon is hot-linked from a different domain, which is how kits "
                "reuse a brand's real favicon to look authentic.",
                severity=Severity.LOW,
                weight=7,
                category="impersonation",
                confidence=0.6,
                evidence=metadata.favicon[:180],
            )
        )

    total_links = max(len(links), 1)
    if len(links) >= 5 and sum(1 for link in links if link.is_external) / total_links > 0.9:
        factors.append(
            _factor(
                "all_links_offsite",
                "Every link points off-site",
                "The page has no internal navigation at all, typical of a single-page "
                "phishing clone whose links were copied from the brand it imitates.",
                severity=Severity.LOW,
                weight=6,
                category="structure",
                confidence=0.55,
                evidence=f"{sum(1 for link in links if link.is_external)}/{len(links)} external",
            )
        )

    lowered_text = visible_text.lower()
    matched_phrases = [label for phrase, label in _SOCIAL_ENGINEERING_PHRASES if phrase in lowered_text]
    if matched_phrases:
        unique_phrases = sorted(set(matched_phrases))
        severity = Severity.HIGH if len(unique_phrases) >= 3 else Severity.MEDIUM
        factors.append(
            _factor(
                "social_engineering_language",
                "Pressure and urgency language",
                "The copy uses classic social-engineering levers "
                f"({', '.join(unique_phrases[:5])}) to rush the visitor past their own judgement.",
                severity=severity,
                weight=18 if severity is Severity.HIGH else 11,
                category="social_engineering",
                confidence=0.75,
                evidence=", ".join(unique_phrases[:8]),
            )
        )

    return factors


def _analyse_headers(headers: Dict[str, str], url: str) -> List[RiskFactor]:
    factors: List[RiskFactor] = []
    present = {key.lower(): value for key, value in (headers or {}).items()}
    is_https = url.lower().startswith("https://")

    missing = [
        header
        for header in ("content-security-policy", "x-frame-options", "strict-transport-security")
        if header not in present
    ]
    if is_https and len(missing) >= 3:
        factors.append(
            _factor(
                "missing_security_headers",
                "No baseline security headers",
                "None of CSP, X-Frame-Options or HSTS are set. Established brands "
                "deploy these; freshly stood-up phishing hosts usually ship defaults.",
                severity=Severity.LOW,
                weight=6,
                category="infrastructure",
                confidence=0.5,
                evidence=", ".join(missing),
            )
        )

    cookie = present.get("set-cookie", "")
    if cookie and "secure" not in cookie.lower() and is_https:
        factors.append(
            _factor(
                "insecure_cookie",
                "Session cookie set without the Secure flag",
                "Cookies issued over HTTPS without `Secure` can leak to a plaintext "
                "request, indicating an unmaintained or hastily deployed stack.",
                severity=Severity.LOW,
                weight=5,
                category="infrastructure",
                confidence=0.55,
                evidence=cookie[:160],
            )
        )

    return factors


def run_heuristics(
    url: str,
    headers: Dict[str, str],
    metadata: PageMetadata,
    forms: Sequence[FormSummary],
    links: Sequence[LinkSummary],
    visible_text: str,
) -> Tuple[int, List[RiskFactor], Optional[str]]:
    """Deterministic, fully explainable scoring pass.

    Returns ``(score, factors, impersonated_brand)``. The score is the summed
    factor weight, dampened above 60 so a long tail of low-severity findings
    cannot saturate the gauge on its own.
    """

    host = hostname_of(url)
    base_domain = registrable_domain(host)

    factors: List[RiskFactor] = []
    factors.extend(_analyse_url_shape(url, host, base_domain))

    brand_factors, impersonated = _analyse_brand_impersonation(host, base_domain, metadata, visible_text)
    factors.extend(brand_factors)

    factors.extend(_analyse_credential_harvesting(url, host, forms, metadata))
    factors.extend(_analyse_page_behaviour(url, host, metadata, links, visible_text))
    factors.extend(_analyse_headers(headers, url))

    factors = dedupe_risk_factors(factors)
    raw = sum(factor.weight * (0.6 + 0.4 * factor.confidence) for factor in factors)

    if raw <= 60:
        score = raw
    else:
        # Diminishing returns past 60 so breadth alone cannot reach 100.
        score = 60 + (raw - 60) * 0.45

    # A credential form combined with impersonation is the definition of
    # phishing; make sure that combination always lands in the danger band.
    has_credentials = any(
        factor.category == "credential_harvesting" for factor in factors
    )
    has_impersonation = any(factor.category == "impersonation" for factor in factors)
    if has_credentials and has_impersonation:
        score = max(score, 72)

    return int(max(0, min(round(score), 100))), factors, impersonated


# ===========================================================================
# LangChain LLM analyst
# ===========================================================================

PHISHING_SYSTEM_PROMPT = """You are a senior phishing analyst on a corporate \
CSIRT. You review evidence captured from a single web page by an automated \
sandbox (headless Chromium, JavaScript disabled) and decide whether the page \
is a credential-harvesting or fraud page.

HOW TO REASON
1. Compare identity claims against infrastructure. Ask: who does this page \
claim to be, and does the registrable domain belong to that organisation? \
Brand content on unaffiliated infrastructure is phishing.
2. Follow the data. Where would submitted input actually go? A form posting to \
a different registrable domain, to plain HTTP, or to no target at all is a \
strong exfiltration signal.
3. Weigh typosquatting, homograph and punycode host names, deep subdomain \
nesting used to hide the real domain, free hosting, and high-abuse TLDs.
4. Weigh social engineering: urgency, threats of suspension, artificial \
deadlines, prize or refund lures, requests for card data, one-time codes, \
national identifiers or crypto recovery phrases.
5. Note evasion: cloaking, meta-refresh redirects, obfuscated markup, empty \
shell pages that need script to render, third-party iframes.

CALIBRATION (be strict and evidence-driven)
- 0-19   : no phishing indicators; consistent, well-known, self-consistent site.
- 20-39  : minor anomalies only, no credential collection or impersonation.
- 40-64  : suspicious combination that a human should review.
- 65-84  : likely phishing; impersonation plus credential collection or clear exfiltration.
- 85-100 : unambiguous phishing or fraud; multiple confirmed indicators.

RULES
- Judge only the supplied evidence. Never invent URLs, brands or field names.
- A well-known brand serving its own sign-in page on its own domain is NOT \
phishing; do not penalise a legitimate login form.
- Absence of evidence is not evidence: if the capture is empty or blocked, say \
so and score conservatively.
- Every indicator must cite something concrete from the evidence.
- Reply with a single JSON object and nothing else. No prose, no code fences.

OUTPUT SCHEMA
{
  "threat_score": <integer 0-100>,
  "confidence": <float 0.0-1.0>,
  "verdict": "<short verdict, max 12 words>",
  "summary": "<2-4 sentences of analyst-grade reasoning>",
  "brand_impersonated": "<brand name or null>",
  "credential_harvesting": <true|false>,
  "social_engineering_tactics": ["<short tactic label>", "..."],
  "recommended_action": "<concrete next step for the analyst>",
  "indicators": [
    {
      "id": "<snake_case_slug>",
      "title": "<short finding title>",
      "description": "<why this matters, 1-2 sentences>",
      "category": "<impersonation|credential_harvesting|evasion|social_engineering|infrastructure|url|transport|structure>",
      "severity": "<info|low|medium|high|critical>",
      "confidence": <float 0.0-1.0>,
      "evidence": "<exact snippet or value from the evidence>"
    }
  ]
}"""


#: Operator-facing remediation prefixes. The raw provider message is appended,
#: so the dashboard shows both what broke and what to do about it.
_AI_STATUS_HINTS: Dict[str, str] = {
    "quota_exceeded": (
        "The AI provider reports no remaining quota or credit, so the analyst pass "
        "was skipped. Top up the account or switch AI_PROVIDER to a free provider; "
        "scoring continued on the rule engine and threat intel."
    ),
    "unauthorized": (
        "The AI provider rejected the credential. Check the key for a typo, "
        "revocation, or a project mismatch, and confirm it matches AI_PROVIDER."
    ),
    "model_unavailable": (
        "AI_MODEL is not available on this provider or key. Providers retire model "
        "IDs regularly, so confirm the ID against the provider's current model list."
    ),
    "rate_limited": (
        "The AI provider throttled the request. Lower MAX_CONCURRENT_SCANS or retry "
        "shortly; free tiers have tight per-minute limits."
    ),
    "provider_overloaded": (
        "The AI provider has no spare capacity for this model right now (a transient "
        "spike, not a configuration fault). Retry in a few minutes, pick a different "
        "AI_MODEL, or switch AI_PROVIDER; scoring continued on the rule engine and "
        "threat intel."
    ),
    "empty_response": (
        "The model returned no text, which usually means its reasoning consumed the "
        "whole output budget. Raise AI_MAX_TOKENS or set AI_REASONING_EFFORT=low."
    ),
    "timeout": (
        "The AI provider did not respond within AI_TIMEOUT_SECONDS. Raise the budget "
        "or pick a faster model."
    ),
    "unreachable": (
        "The backend could not reach AI_BASE_URL. Check container egress, DNS, and "
        "the base URL spelling."
    ),
}


def classify_llm_error(message: str) -> str:
    """Map a provider exception message onto a stable status code.

    Ordering is deliberate and load-bearing. OpenAI reports an exhausted
    balance as HTTP 429 with ``type=insufficient_quota``, so testing for a bare
    "429" first would label a spent account as throttling and tell the analyst
    to retry when the real fix is to add credit. Specific causes are therefore
    matched before generic transport symptoms.
    """

    lowered = (message or "").lower()
    if (
        "insufficient_quota" in lowered
        or "exceeded your current quota" in lowered
        # OpenRouter returns HTTP 402 when the account needs a top-up. Treated as
        # a quota problem because the remedy is money, not patience.
        or "requires more credits" in lowered
        or "insufficient credits" in lowered
        or "payment required" in lowered
        or "402" in lowered
    ):
        return "quota_exceeded"
    if (
        # OpenAI phrasings.
        "invalid_api_key" in lowered
        or "incorrect api key" in lowered
        or "invalid authentication" in lowered
        # Gemini returns HTTP 400 INVALID_ARGUMENT for a bad key, so the generic
        # 401 test below would never catch it.
        or "api key not valid" in lowered
        or "api_key_invalid" in lowered
        or "api key expired" in lowered
        or "unauthenticated" in lowered
        or "permission_denied" in lowered
    ):
        return "unauthorized"
    if (
        "model_not_found" in lowered
        or "does not exist or you do not have access" in lowered
        # Gemini's wording when a model ID is wrong or unavailable to the key.
        or "is not found for api version" in lowered
        or "not supported for generatecontent" in lowered
        # Gemini's wording for a model retired for newly created keys, which
        # ListModels still advertises. Seen live on gemini-2.5-flash.
        or "no longer available" in lowered
        or "has been deprecated" in lowered
        or "is not available to new" in lowered
    ):
        return "model_unavailable"
    if "authentication" in lowered or "401" in lowered or "permission" in lowered:
        return "unauthorized"
    # Gemini free tiers signal an exhausted per-minute/per-day cap this way; it
    # is throttling rather than a billing problem, so it maps to rate_limited.
    if "resource_exhausted" in lowered or "resource has been exhausted" in lowered:
        return "rate_limited"
    # Transient capacity, not a configuration fault. Distinguished from
    # throttling because the remedy is "wait or switch provider", not "slow
    # down": free Gemini tiers return this across every model during spikes.
    if (
        "high demand" in lowered
        or "overloaded" in lowered
        or "service unavailable" in lowered
        or "temporarily unavailable" in lowered
        or "please try again later" in lowered
        or "503" in lowered
    ):
        return "provider_overloaded"
    if "rate limit" in lowered or "rate_limit" in lowered or "429" in lowered:
        return "rate_limited"
    if "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    if "connection" in lowered or "network" in lowered or "unreachable" in lowered:
        return "unreachable"
    return "error"


def _severity_weight(severity: Severity, confidence: float) -> float:
    base = {
        Severity.CRITICAL: 30.0,
        Severity.HIGH: 22.0,
        Severity.MEDIUM: 13.0,
        Severity.LOW: 7.0,
        Severity.INFO: 2.0,
    }[severity]
    return round(base * (0.6 + 0.4 * max(0.0, min(confidence, 1.0))), 2)


def build_evidence_payload(
    url: str,
    final_url: str,
    http_status: Optional[int],
    headers: Dict[str, str],
    metadata: PageMetadata,
    forms: Sequence[FormSummary],
    links: Sequence[LinkSummary],
    visible_text: str,
    dom_excerpt: str,
    heuristic_factors: Sequence[RiskFactor],
    virustotal: Optional[VirusTotalReport],
) -> str:
    """Distil the capture into a compact, token-efficient evidence document."""

    host = hostname_of(final_url or url)
    base_domain = registrable_domain(host)

    form_lines: List[str] = []
    for index, form in enumerate(forms[:8], start=1):
        form_lines.append(
            f"  {index}. method={form.method.upper()} "
            f"action={form.resolved_action[:180] or '(empty - same page)'} "
            f"cross_origin={form.is_cross_origin} insecure_action={form.action_is_insecure} "
            f"password_field={form.has_password_field} inputs={form.input_count} "
            f"field_names={form.input_names[:12]}"
        )

    external_links = [link for link in links if link.is_external][:12]
    link_lines = [f"  - {link.host or '?'} | {link.text[:60]!r} | {link.href[:140]}" for link in external_links]

    interesting_headers = {
        key: value
        for key, value in (headers or {}).items()
        if key
        in {
            "server",
            "content-type",
            "location",
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-powered-by",
            "set-cookie",
            "cf-ray",
        }
    }

    heuristic_lines = [
        f"  - [{factor.severity.value.upper()}] {factor.title}: {factor.evidence or factor.description[:120]}"
        for factor in list(heuristic_factors)[:12]
    ]

    vt_line = "not queried"
    if virustotal is not None and virustotal.available:
        vt_line = (
            f"malicious={virustotal.domain_stats.malicious} "
            f"suspicious={virustotal.domain_stats.suspicious} "
            f"harmless={virustotal.domain_stats.harmless} "
            f"reputation={virustotal.reputation} "
            f"domain_age_days={virustotal.domain_age_days} "
            f"engines={virustotal.malicious_engines[:6]}"
        )
    elif virustotal is not None:
        vt_line = f"unavailable ({virustotal.status})"

    sections = [
        "=== TARGET ===",
        f"requested_url: {url}",
        f"final_url: {final_url or url}",
        f"host: {host}",
        f"registrable_domain: {base_domain}",
        f"tls: {'https' if (final_url or url).lower().startswith('https://') else 'http (NOT ENCRYPTED)'}",
        f"http_status: {http_status if http_status is not None else 'unknown'}",
        f"redirect_chain: {metadata.redirect_chain[:6] or 'none'}",
        "",
        "=== PAGE IDENTITY ===",
        f"title: {metadata.title[:200] or '(none)'}",
        f"meta_description: {metadata.description[:240] or '(none)'}",
        f"language: {metadata.language or '(unset)'}",
        f"generator: {metadata.generator or '(none)'}",
        f"canonical_url: {metadata.canonical_url[:180] or '(none)'}",
        f"favicon: {metadata.favicon[:180] or '(none)'}",
        f"brand_keywords_found_in_content: {metadata.brand_keywords or 'none'}",
        "",
        "=== STRUCTURE ===",
        f"visible_text_length: {metadata.text_length}",
        f"dom_length: {metadata.dom_length}",
        f"forms: {metadata.form_count} (password fields in {metadata.password_field_count})",
        f"hidden_inputs: {metadata.hidden_input_count}",
        f"links: {metadata.link_count} ({metadata.external_link_count} external)",
        f"distinct_link_hosts: {metadata.unique_link_hosts[:12]}",
        f"iframes: {metadata.iframe_count} {metadata.iframe_sources[:4]}",
        f"scripts: {metadata.script_count}, external_script_hosts={metadata.external_script_hosts[:6]}",
        f"images: {metadata.image_count}",
        f"meta_refresh: {metadata.meta_refresh[:160] or 'none'}",
        f"obfuscation_markers: {metadata.obfuscation_markers or 'none'}",
        "",
        "=== FORMS (where submitted data would go) ===",
        "\n".join(form_lines) if form_lines else "  (no forms on the page)",
        "",
        "=== EXTERNAL LINKS (sample) ===",
        "\n".join(link_lines) if link_lines else "  (none)",
        "",
        "=== RESPONSE HEADERS (selected) ===",
        json.dumps(interesting_headers, ensure_ascii=False)[:1200] if interesting_headers else "  (none captured)",
        "",
        "=== THREAT INTELLIGENCE (VirusTotal) ===",
        f"  {vt_line}",
        "",
        "=== DETERMINISTIC ENGINE FINDINGS (for cross-checking, may be incomplete) ===",
        "\n".join(heuristic_lines) if heuristic_lines else "  (none)",
        "",
        "=== VISIBLE TEXT (truncated) ===",
        visible_text[:MAX_EVIDENCE_TEXT_CHARS] or "(page rendered no readable text)",
        "",
        "=== RAW HTML HEAD/BODY EXCERPT (truncated) ===",
        dom_excerpt[:MAX_EVIDENCE_DOM_CHARS] or "(empty DOM)",
    ]
    return "\n".join(sections)


def _extract_json_object(text: str) -> Dict[str, Any]:
    """Parse the model reply, tolerating fences and trailing commentary."""

    if not text or not text.strip():
        raise ValueError("model returned an empty response")

    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*", "", candidate)
        candidate = re.sub(r"\s*```$", "", candidate).strip()

    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Fall back to the widest balanced brace span.
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end > start:
        snippet = candidate[start : end + 1]
        try:
            parsed = json.loads(snippet)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            # Last resort: strip trailing commas, a frequent LLM slip.
            repaired = re.sub(r",\s*([}\]])", r"\1", snippet)
            parsed = json.loads(repaired)
            if isinstance(parsed, dict):
                return parsed

    raise ValueError("no JSON object found in the model response")


def _coerce_severity(value: Any) -> Severity:
    try:
        return Severity(str(value).strip().lower())
    except ValueError:
        return Severity.MEDIUM


def _coerce_confidence(value: Any, default: float = 0.7) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number > 1.0:
        number = number / 100.0 if number <= 100.0 else 1.0
    return max(0.0, min(number, 1.0))


def _coerce_score(value: Any, default: int = 0) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return int(max(0, min(round(number), 100)))


def _slugify(value: str, fallback: str = "ai_indicator") -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")
    return (slug or fallback)[:64]


def _parse_llm_payload(payload: Dict[str, Any], model_name: str, latency_ms: int) -> AIAnalysis:
    indicators: List[RiskFactor] = []
    raw_indicators = payload.get("indicators")
    if isinstance(raw_indicators, list):
        for entry in raw_indicators[:20]:
            if not isinstance(entry, dict):
                continue
            title = str(entry.get("title") or entry.get("name") or "").strip()
            description = str(entry.get("description") or entry.get("detail") or "").strip()
            if not title and not description:
                continue
            severity = _coerce_severity(entry.get("severity"))
            confidence = _coerce_confidence(entry.get("confidence"), default=0.7)
            indicators.append(
                RiskFactor(
                    id=_slugify(entry.get("id") or title),
                    title=(title or description)[:200],
                    description=(description or title)[:1000],
                    category=_slugify(entry.get("category") or "general", fallback="general"),
                    severity=severity,
                    source=FactorSource.AI,
                    confidence=confidence,
                    weight=_severity_weight(severity, confidence),
                    evidence=(str(entry.get("evidence"))[:1200] if entry.get("evidence") else None),
                )
            )

    tactics_raw = payload.get("social_engineering_tactics")
    tactics: List[str] = []
    if isinstance(tactics_raw, list):
        tactics = [str(item).strip()[:120] for item in tactics_raw[:10] if str(item).strip()]
    elif isinstance(tactics_raw, str) and tactics_raw.strip():
        tactics = [tactics_raw.strip()[:120]]

    brand = payload.get("brand_impersonated")
    if isinstance(brand, str):
        brand_value: Optional[str] = brand.strip()[:80] or None
        if brand_value and brand_value.lower() in {"null", "none", "n/a", "unknown", "-"}:
            brand_value = None
    else:
        brand_value = None

    score = _coerce_score(payload.get("threat_score"), default=0)
    if score == 0 and indicators:
        # A model that lists findings but forgets the number should not read as clean.
        score = _coerce_score(
            max(_severity_weight(item.severity, item.confidence) for item in indicators) * 2
        )

    return AIAnalysis(
        available=True,
        status="ok",
        provider=AI_PROVIDER,
        ai_model=model_name,
        threat_score=score,
        confidence=_coerce_confidence(payload.get("confidence"), default=0.7),
        verdict=str(payload.get("verdict") or "")[:200],
        summary=str(payload.get("summary") or "")[:2000],
        brand_impersonated=brand_value,
        credential_harvesting=bool(payload.get("credential_harvesting")),
        social_engineering_tactics=tactics,
        recommended_action=str(payload.get("recommended_action") or "")[:600],
        indicators=indicators,
        latency_ms=latency_ms,
    )


def _is_json_mode_rejection(message: str) -> bool:
    """True when the provider refused the ``response_format`` parameter.

    Free and self-hosted endpoints are inconsistent about JSON mode. Rather than
    give up, the caller retries without it and relies on the prompt plus the
    tolerant parser in :func:`_extract_json_object`.
    """

    lowered = (message or "").lower()
    markers = ("response_format", "json_object", "json mode", "json_schema")
    if not any(marker in lowered for marker in markers):
        return False
    return any(
        signal in lowered
        for signal in (
            "not supported",
            "unsupported",
            "invalid",
            "unrecognized",
            "unknown",
            "does not support",
            "cannot be used",
            "400",
        )
    )


async def _invoke_chat_model(messages: List[Any], json_mode: bool) -> str:
    """Single LangChain round-trip against the configured provider."""

    from langchain_core.output_parsers import StrOutputParser
    from langchain_openai import ChatOpenAI

    client_kwargs: Dict[str, Any] = {
        "model": AI_MODEL,
        "temperature": 0.0,
        "timeout": AI_TIMEOUT_SECONDS,
        "max_retries": 2,
        "max_tokens": AI_MAX_TOKENS,
        # Local endpoints ignore the credential but the client still requires one.
        "api_key": AI_API_KEY or _NO_KEY_SENTINEL,
        "base_url": AI_BASE_URL,
    }
    model_kwargs: Dict[str, Any] = {}
    if json_mode:
        # Constrains the reply to a single JSON object where supported.
        model_kwargs["response_format"] = {"type": "json_object"}
    if AI_REASONING_EFFORT:
        model_kwargs["reasoning_effort"] = AI_REASONING_EFFORT
    if model_kwargs:
        client_kwargs["model_kwargs"] = model_kwargs

    extra_headers = ai_request_headers()
    if extra_headers:
        client_kwargs["default_headers"] = extra_headers

    chain = ChatOpenAI(**client_kwargs) | StrOutputParser()
    return await chain.ainvoke(messages)


async def analyze_with_llm(evidence: str) -> AIAnalysis:
    """Run the LangChain phishing-analyst chain over the evidence document.

    Never raises: a missing key, an exhausted quota or a provider outage is
    reported through the returned :class:`AIAnalysis` so the scan degrades to
    the deterministic engines instead of failing.
    """

    if not ai_enabled():
        preset = AI_PRESET
        detail = (
            f"{preset.key_env} is not set, so the {preset.label} analyst pass was "
            f"skipped; scoring continued on the rule engine and threat intel."
        )
        if preset.signup_url:
            detail += f" Free key: {preset.signup_url}"
        return AIAnalysis(
            available=False,
            status="not_configured",
            detail=detail[:400],
            provider=AI_PROVIDER,
            ai_model=AI_MODEL,
        )

    started = time.perf_counter()
    try:
        # Imported lazily so the service still boots if the optional AI extras
        # are unavailable in a stripped-down environment.
        from langchain_core.messages import HumanMessage, SystemMessage
    except ImportError as exc:  # pragma: no cover - dependency issue
        LOGGER.error("LangChain import failed: %s", exc)
        return AIAnalysis(
            available=False,
            status="unavailable",
            detail=f"LangChain packages are not importable: {exc}",
            provider=AI_PROVIDER,
            ai_model=AI_MODEL,
        )

    messages: List[Any] = [
        SystemMessage(content=PHISHING_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                "Analyse the following sandbox capture and reply with the JSON "
                "object defined in your instructions.\n\n" + evidence
            )
        ),
    ]

    # Try JSON mode first, then fall back to prompt-only JSON if the provider
    # rejects the parameter. Free endpoints frequently do.
    attempts = [True, False] if AI_JSON_MODE else [False]
    raw: Optional[str] = None
    for index, json_mode in enumerate(attempts):
        try:
            raw = await _invoke_chat_model(messages, json_mode)
            break
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            message = str(exc)
            is_last = index + 1 >= len(attempts)
            if not is_last and _is_json_mode_rejection(message):
                LOGGER.info(
                    "%s rejected response_format; retrying without JSON mode.",
                    AI_PROVIDER_LABEL,
                )
                continue

            latency = int((time.perf_counter() - started) * 1000)
            status = classify_llm_error(message)
            LOGGER.warning(
                "%s analysis failed after %sms (%s): %s",
                AI_PROVIDER_LABEL,
                latency,
                status,
                message[:300],
            )
            hint = _AI_STATUS_HINTS.get(status, "")
            return AIAnalysis(
                available=False,
                status=status,
                detail=(f"{hint} {message}".strip() if hint else message)[:400],
                provider=AI_PROVIDER,
                ai_model=AI_MODEL,
                latency_ms=latency,
            )

    latency = int((time.perf_counter() - started) * 1000)

    # A reasoning model that burns its whole budget thinking returns HTTP 200
    # with an empty message. Reported distinctly from malformed JSON because the
    # remedy is different: raise the token budget, not change the prompt.
    if raw is None or not str(raw).strip():
        LOGGER.warning(
            "%s returned an empty completion (likely reasoning-token starvation at "
            "AI_MAX_TOKENS=%s).",
            AI_PROVIDER_LABEL,
            AI_MAX_TOKENS,
        )
        return AIAnalysis(
            available=False,
            status="empty_response",
            detail=(
                f"{_AI_STATUS_HINTS['empty_response']} "
                f"(provider={AI_PROVIDER_LABEL}, model={AI_MODEL}, "
                f"AI_MAX_TOKENS={AI_MAX_TOKENS})"
            )[:400],
            provider=AI_PROVIDER,
            ai_model=AI_MODEL,
            latency_ms=latency,
        )

    try:
        payload = _extract_json_object(raw if isinstance(raw, str) else str(raw))
    except (ValueError, json.JSONDecodeError) as exc:
        LOGGER.warning("Could not parse the %s response: %s", AI_PROVIDER_LABEL, exc)
        return AIAnalysis(
            available=False,
            status="unparsable_response",
            detail=(
                f"{AI_PROVIDER_LABEL} did not return usable JSON ({exc}). "
                "A more capable model usually fixes this."
            )[:400],
            provider=AI_PROVIDER,
            ai_model=AI_MODEL,
            latency_ms=latency,
        )

    analysis = _parse_llm_payload(payload, AI_MODEL, latency)
    LOGGER.info(
        "%s verdict: score=%s confidence=%.2f indicators=%s in %sms",
        AI_PROVIDER_LABEL,
        analysis.threat_score,
        analysis.confidence,
        len(analysis.indicators),
        latency,
    )
    return analysis


# ===========================================================================
# VirusTotal threat intelligence
# ===========================================================================


def _virustotal_url_id(url: str) -> str:
    """VirusTotal v3 URL identifier: unpadded base64url of the URL."""

    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _parse_vt_stats(raw: Any) -> VirusTotalStats:
    if not isinstance(raw, dict):
        return VirusTotalStats()
    return VirusTotalStats(
        harmless=int(raw.get("harmless") or 0),
        malicious=int(raw.get("malicious") or 0),
        suspicious=int(raw.get("suspicious") or 0),
        undetected=int(raw.get("undetected") or 0),
        timeout=int(raw.get("timeout") or 0),
    )


def _malicious_engine_names(results: Any, limit: int = 12) -> List[str]:
    names: List[str] = []
    if not isinstance(results, dict):
        return names
    for engine, verdict in results.items():
        if not isinstance(verdict, dict):
            continue
        if str(verdict.get("category", "")).lower() in {"malicious", "suspicious"}:
            label = str(verdict.get("result") or verdict.get("category") or "flagged")
            names.append(f"{engine}: {label}"[:80])
        if len(names) >= limit:
            break
    return names


def _epoch_to_iso(value: Any) -> Optional[str]:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _domain_age_days(creation_epoch: Any) -> Optional[int]:
    try:
        seconds = int(creation_epoch)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        created = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return max(0, (datetime.now(timezone.utc) - created).days)


async def lookup_virustotal(domain: str, url: Optional[str] = None) -> VirusTotalReport:
    """Fetch domain (and optionally URL) reputation from VirusTotal v3.

    Never raises: transport, auth and quota problems are reported in the
    returned model so the scan still completes.
    """

    report = VirusTotalReport(queried_domain=domain)

    if not VIRUSTOTAL_API_KEY:
        report.status = "not_configured"
        report.detail = "VIRUSTOTAL_API_KEY is not set; reputation lookup skipped."
        return report

    if not domain or coerce_ip_literal(domain) is not None:
        report.status = "skipped"
        report.detail = "Reputation lookup requires a domain name (IP literal supplied)."
        return report

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "accept": "application/json",
        "user-agent": "ThreatLens/1.0",
    }

    try:
        async with httpx.AsyncClient(
            base_url=VIRUSTOTAL_BASE_URL,
            headers=headers,
            timeout=httpx.Timeout(VIRUSTOTAL_TIMEOUT_SECONDS, connect=8.0),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        ) as client:
            domain_response = await client.get(f"/domains/{domain}")

            if domain_response.status_code == 401:
                report.status = "unauthorized"
                report.detail = "VirusTotal rejected the API key (HTTP 401)."
                return report
            if domain_response.status_code == 429:
                report.status = "rate_limited"
                report.detail = (
                    "VirusTotal quota exhausted (HTTP 429). Community keys allow "
                    "about 4 lookups per minute."
                )
                return report
            if domain_response.status_code == 404:
                report.status = "not_found"
                report.detail = (
                    f"VirusTotal has no record for '{domain}'. Unknown domains are "
                    "common for freshly registered phishing infrastructure."
                )
                return report
            if domain_response.status_code >= 400:
                report.status = "error"
                report.detail = (
                    f"VirusTotal returned HTTP {domain_response.status_code}: "
                    f"{domain_response.text[:200]}"
                )
                return report

            attributes = (domain_response.json().get("data") or {}).get("attributes") or {}

            report.available = True
            report.status = "ok"
            report.domain_stats = _parse_vt_stats(attributes.get("last_analysis_stats"))
            report.malicious_engines = _malicious_engine_names(attributes.get("last_analysis_results"))
            reputation = attributes.get("reputation")
            report.reputation = int(reputation) if isinstance(reputation, (int, float)) else None
            categories = attributes.get("categories")
            if isinstance(categories, dict):
                report.categories = {
                    str(key)[:60]: str(value)[:80] for key, value in list(categories.items())[:12]
                }
            registrar = attributes.get("registrar")
            report.registrar = str(registrar)[:120] if registrar else None
            report.creation_date = _epoch_to_iso(attributes.get("creation_date"))
            report.domain_age_days = _domain_age_days(attributes.get("creation_date"))
            report.last_analysis_date = _epoch_to_iso(attributes.get("last_analysis_date"))
            report.permalink = f"https://www.virustotal.com/gui/domain/{domain}"

            # The exact URL is scored separately by VT; a clean domain can still
            # host a flagged path.
            if url:
                try:
                    url_response = await client.get(f"/urls/{_virustotal_url_id(url)}")
                    if url_response.status_code == 200:
                        url_attributes = (url_response.json().get("data") or {}).get("attributes") or {}
                        report.url_stats = _parse_vt_stats(url_attributes.get("last_analysis_stats"))
                        extra_engines = _malicious_engine_names(
                            url_attributes.get("last_analysis_results")
                        )
                        for engine in extra_engines:
                            if engine not in report.malicious_engines and len(report.malicious_engines) < 20:
                                report.malicious_engines.append(engine)
                except httpx.HTTPError as exc:
                    LOGGER.debug("VirusTotal URL lookup failed for %s: %s", url, exc)

    except httpx.TimeoutException:
        report.status = "timeout"
        report.detail = f"VirusTotal did not respond within {VIRUSTOTAL_TIMEOUT_SECONDS:.0f}s."
    except httpx.HTTPError as exc:
        report.status = "error"
        report.detail = f"VirusTotal request failed: {str(exc)[:200]}"
    except (ValueError, KeyError, TypeError) as exc:
        report.status = "error"
        report.detail = f"Unexpected VirusTotal payload: {str(exc)[:200]}"

    if report.available:
        LOGGER.info(
            "VirusTotal %s: malicious=%s suspicious=%s reputation=%s age_days=%s",
            domain,
            report.domain_stats.malicious,
            report.domain_stats.suspicious,
            report.reputation,
            report.domain_age_days,
        )
    else:
        LOGGER.info("VirusTotal lookup for %s unavailable (%s).", domain, report.status)
    return report


def threat_intel_factors(report: VirusTotalReport) -> Tuple[int, List[RiskFactor]]:
    """Convert a VirusTotal report into a 0-100 score plus analyst findings."""

    factors: List[RiskFactor] = []
    if not report.available:
        return 0, factors

    malicious = report.malicious_count
    suspicious = report.suspicious_count
    score = 0

    if malicious >= 1:
        score = min(100, 55 + malicious * 9)
        severity = Severity.CRITICAL if malicious >= 3 else Severity.HIGH
        factors.append(
            _factor(
                "virustotal_malicious",
                f"Flagged as malicious by {malicious} security vendor(s)",
                "Independent anti-phishing and anti-malware engines already classify "
                "this destination as malicious. This is a confirmed detection, not a "
                "heuristic guess.",
                severity=severity,
                weight=34 if malicious >= 3 else 26,
                category="threat_intel",
                confidence=0.95,
                source=FactorSource.THREAT_INTEL,
                evidence="; ".join(report.malicious_engines[:6]) or f"{malicious} detections",
            )
        )
    elif suspicious >= 1:
        score = min(100, 30 + suspicious * 8)
        factors.append(
            _factor(
                "virustotal_suspicious",
                f"Marked suspicious by {suspicious} vendor(s)",
                "One or more engines consider this destination suspicious without a "
                "firm malicious verdict - worth analyst review.",
                severity=Severity.MEDIUM,
                weight=15,
                category="threat_intel",
                confidence=0.8,
                source=FactorSource.THREAT_INTEL,
                evidence="; ".join(report.malicious_engines[:4]) or f"{suspicious} detections",
            )
        )

    if report.reputation is not None and report.reputation <= -10:
        score = max(score, 45)
        factors.append(
            _factor(
                "poor_community_reputation",
                "Negative community reputation",
                f"The VirusTotal community score is {report.reputation}, meaning users "
                "have repeatedly reported this domain.",
                severity=Severity.MEDIUM,
                weight=12,
                category="threat_intel",
                confidence=0.7,
                source=FactorSource.THREAT_INTEL,
                evidence=f"reputation={report.reputation}",
            )
        )

    age = report.domain_age_days
    if age is not None and age <= 30:
        score = max(score, 42)
        factors.append(
            _factor(
                "newly_registered_domain",
                f"Domain registered {age} day(s) ago",
                "Phishing infrastructure is typically used within days of registration "
                "and burned soon after. Brand sign-in pages live on domains that are "
                "years old.",
                severity=Severity.HIGH if age <= 7 else Severity.MEDIUM,
                weight=22 if age <= 7 else 14,
                category="threat_intel",
                confidence=0.85,
                source=FactorSource.THREAT_INTEL,
                evidence=f"created={report.creation_date} ({age} days old)",
            )
        )
    elif age is not None and age <= 180:
        factors.append(
            _factor(
                "young_domain",
                f"Relatively young domain ({age} days)",
                "The domain is less than six months old, which is a mild risk signal "
                "when combined with credential collection.",
                severity=Severity.LOW,
                weight=7,
                category="threat_intel",
                confidence=0.6,
                source=FactorSource.THREAT_INTEL,
                evidence=f"created={report.creation_date}",
            )
        )

    flagged_categories = {
        key: value
        for key, value in report.categories.items()
        if any(
            token in value.lower()
            for token in ("phish", "malic", "malware", "spam", "scam", "fraud", "suspicious")
        )
    }
    if flagged_categories:
        score = max(score, 60)
        factors.append(
            _factor(
                "malicious_category",
                "Categorised as phishing/malicious by URL classifiers",
                "Commercial URL categorisation feeds place this domain in an abuse "
                "category.",
                severity=Severity.HIGH,
                weight=20,
                category="threat_intel",
                confidence=0.85,
                source=FactorSource.THREAT_INTEL,
                evidence="; ".join(f"{key}={value}" for key, value in list(flagged_categories.items())[:4]),
            )
        )

    return int(max(0, min(score, 100))), factors


# ===========================================================================
# Score fusion
# ===========================================================================


def fuse_scores(
    heuristic_score: int,
    heuristic_factors: Sequence[RiskFactor],
    ai: AIAnalysis,
    intel_score: int,
    intel_factors: Sequence[RiskFactor],
    reputation_score: int = 0,
    reputation_factors: Optional[Sequence[RiskFactor]] = None,
    reputation_classification: str = "unknown",
) -> Tuple[int, RiskLevel, ScoreBreakdown, List[RiskFactor]]:
    """Blend the engines into one defensible 0-100 score.

    Weighted average first, then hard floors so a confirmed detection or an
    unambiguous credential-exfiltration finding can never be diluted by the
    engines that had nothing to say. The local reputation engine is authoritative
    at the extremes: a blocklist hit floors the score into the danger band, and a
    trusted-allowlist hit caps it so the live engines cannot false-positive a
    major brand.
    """

    reputation_factors = list(reputation_factors or [])
    ai_available = ai.available and ai.status == "ok"
    intel_available = intel_score > 0

    weights: Dict[str, float] = {"heuristic": 1.0, "ai": 0.0, "threat_intel": 0.0}
    if ai_available and intel_available:
        weights = {"heuristic": 0.35, "ai": 0.40, "threat_intel": 0.25}
    elif ai_available:
        weights = {"heuristic": 0.45, "ai": 0.55, "threat_intel": 0.0}
    elif intel_available:
        weights = {"heuristic": 0.60, "ai": 0.0, "threat_intel": 0.40}

    # A low-confidence LLM opinion should not outvote deterministic evidence.
    if ai_available and ai.confidence < 0.5 and weights["ai"] > 0:
        shifted = weights["ai"] * (0.5 - ai.confidence)
        weights["ai"] -= shifted
        weights["heuristic"] += shifted

    blended = (
        heuristic_score * weights["heuristic"]
        + (ai.threat_score if ai_available else 0) * weights["ai"]
        + intel_score * weights["threat_intel"]
    )

    all_factors = dedupe_risk_factors(
        list(reputation_factors)
        + list(heuristic_factors)
        + list(ai.indicators)
        + list(intel_factors)
    )

    escalations: List[str] = []
    score = blended

    def escalate(floor: int, reason: str) -> None:
        nonlocal score
        if score < floor:
            score = float(floor)
            escalations.append(reason)

    # --- Reputation is authoritative at the extremes ----------------------
    # A known-bad blocklist/pattern hit wins over everything else: it is the
    # whole point of a curated feed. Applied first so it sets the danger floor
    # even when the live engines saw a clean-looking page (cloaking).
    if reputation_classification == "malicious":
        if any(f.id == "known_malicious_domain" for f in reputation_factors):
            escalate(92, "Domain is on the curated known-bad blocklist.")
        elif any(f.id == "reputation_pattern_match" for f in reputation_factors):
            escalate(80, "Host matches a known malicious domain pattern.")

    critical_ids = {factor.id for factor in all_factors if factor.severity is Severity.CRITICAL}
    if "virustotal_malicious" in critical_ids:
        escalate(88, "Multiple security vendors confirm this destination is malicious.")
    elif any(factor.id == "virustotal_malicious" for factor in all_factors):
        escalate(72, "At least one security vendor flags this destination as malicious.")

    if "cross_origin_form_action" in critical_ids:
        escalate(80, "Credentials would be exfiltrated to a third-party domain.")
    if "password_over_http" in critical_ids:
        escalate(78, "A password is collected over an unencrypted connection.")
    if "typosquatting" in critical_ids or "character_substitution" in critical_ids:
        escalate(74, "The host name is a one-character lookalike of a major brand.")
    if "high_value_data_request" in critical_ids:
        escalate(70, "The page requests card, OTP or crypto-recovery data.")

    if ai_available and ai.credential_harvesting and ai.confidence >= 0.7 and ai.threat_score >= 60:
        escalate(
            min(ai.threat_score, 90),
            "The AI analyst concluded, with high confidence, that the page harvests credentials.",
        )

    severity_counts = {
        Severity.CRITICAL: sum(1 for f in all_factors if f.severity is Severity.CRITICAL),
        Severity.HIGH: sum(1 for f in all_factors if f.severity is Severity.HIGH),
    }
    if severity_counts[Severity.CRITICAL] >= 2:
        escalate(85, "Two or more critical indicators were confirmed independently.")
    elif severity_counts[Severity.CRITICAL] >= 1 and severity_counts[Severity.HIGH] >= 2:
        escalate(76, "A critical indicator is corroborated by multiple high-severity findings.")

    # --- Trusted allowlist damper -----------------------------------------
    # Applied AFTER the danger floors so it can never rescue a domain the live
    # engines independently flagged as critical (a compromised trusted host).
    # Below that bar, it caps the score so weak heuristic noise on a major brand
    # cannot push it out of the "safe" band.
    if reputation_classification == "trusted" and severity_counts[Severity.CRITICAL] == 0:
        cap = 15 if severity_counts[Severity.HIGH] == 0 else 45
        if score > cap:
            score = float(cap)
            escalations.append(
                "Domain is on the trusted allowlist; score capped to avoid a "
                "false positive on a major brand."
            )

    # Nothing anywhere found anything: keep the score honestly low.
    if not all_factors:
        score = min(score, 8)

    final_score = int(max(0, min(round(score), 100)))
    breakdown = ScoreBreakdown(
        reputation_score=reputation_score,
        heuristic_score=heuristic_score,
        ai_score=ai.threat_score if ai_available else 0,
        threat_intel_score=intel_score,
        weights={key: round(value, 2) for key, value in weights.items()},
        escalations=escalations,
    )
    return final_score, score_to_risk_level(final_score), breakdown, all_factors


def build_summary(
    score: int,
    level: RiskLevel,
    factors: Sequence[RiskFactor],
    ai: AIAnalysis,
    impersonated: Optional[str],
    domain: str,
) -> Tuple[str, str]:
    """Produce the headline summary and the recommended action.

    The LLM's prose is preferred when it ran; otherwise a deterministic summary
    is composed from the strongest findings so the UI is never empty.
    """

    if ai.available and ai.status == "ok" and ai.summary.strip():
        summary = ai.summary.strip()
        action = ai.recommended_action.strip() or _default_action(level)
        return summary[:2000], action[:600]

    top = [factor for factor in factors if factor.severity in {Severity.CRITICAL, Severity.HIGH}][:3]
    if not top:
        top = list(factors)[:3]

    if not top:
        summary = (
            f"No phishing indicators were found on {domain}. The page did not request "
            "credentials, did not impersonate a known brand, and no reputation source "
            "flagged it."
        )
    else:
        findings = "; ".join(f"{factor.title.lower()}" for factor in top)
        brand_clause = (
            f" The page appears to impersonate {impersonated.title()}." if impersonated else ""
        )
        summary = (
            f"{domain} scored {score}/100 ({level.value}). Strongest evidence: {findings}."
            f"{brand_clause} Assessment produced by the deterministic engine"
            + (" (AI pass unavailable)." if ai.status != "ok" else ".")
        )

    return summary[:2000], _default_action(level)[:600]


def _default_action(level: RiskLevel) -> str:
    return {
        RiskLevel.CRITICAL: (
            "Block the domain at the proxy and DNS layer, purge related messages from "
            "mailboxes, and force a password reset for anyone who submitted data."
        ),
        RiskLevel.HIGH: (
            "Block the URL, hunt for users who visited it, and submit the domain to your "
            "takedown provider."
        ),
        RiskLevel.MEDIUM: (
            "Hold in review: confirm the registrable domain against the brand it claims, "
            "then decide on blocking."
        ),
        RiskLevel.LOW: "Log the finding. No blocking action required unless corroborated.",
        RiskLevel.SAFE: "No action required.",
        RiskLevel.UNKNOWN: "Re-run the scan; the capture was inconclusive.",
    }[level]
