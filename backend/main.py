"""ThreatLens API - FastAPI application and scan orchestration.

Pipeline for ``POST /api/scan``
-------------------------------
1. Pydantic validates and normalises the URL (structural SSRF gate).
2. DNS is resolved and every answer is checked to be publicly routable.
3. Playwright fetches the page in a disposable, JavaScript-free context.
4. The deterministic heuristic engine scores the capture.
5. The LangChain analyst and the VirusTotal lookup run concurrently.
6. Scores are fused, the report is persisted, and the report is returned.

Every stage degrades instead of exploding: if the AI or the intel provider is
unavailable the scan still returns a scored report and says which engines ran.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Deque, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from analyzer import (
    AI_MODEL,
    AI_PRESET,
    AI_PROVIDER,
    AI_PROVIDER_LABEL,
    ai_enabled,
    ai_provider_info,
    analyze_with_llm,
    build_evidence_payload,
    build_summary,
    fuse_scores,
    lookup_virustotal,
    run_heuristics,
    threat_intel_enabled,
    threat_intel_factors,
)
from reputation import (
    ReputationResult,
    allowlist_size,
    blocklist_size,
    check_reputation,
    reputation_enabled,
    reputation_status_detail,
)
from database import database_status, dispose_engine, init_db, safe_database_target, session_scope
from models import (
    AIAnalysis,
    EngineCapabilities,
    EngineStatus,
    ErrorResponse,
    HealthResponse,
    PageMetadata,
    RiskFactor,
    ScanHistory,
    ScanHistoryItem,
    ScanHistoryPage,
    ScanReport,
    ScoreBreakdown,
    URLRequest,
    UnsafeTargetError,
    VirusTotalReport,
    assert_host_is_public,
    hostname_of,
    registrable_domain,
    risk_level_to_verdict,
    score_to_risk_level,
)
from scraper import (
    BrowserUnavailable,
    NAV_TIMEOUT_MS,
    ScrapeResult,
    ScraperError,
    browser_is_ready,
    scrape_url,
    shutdown_browser,
    start_browser,
)

# ===========================================================================
# Configuration
# ===========================================================================

APP_VERSION = "1.0.0"
_TRUTHY = {"1", "true", "yes", "on", "y"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in _TRUTHY


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
LOGGER = logging.getLogger("threatlens.api")

API_KEY = os.getenv("API_KEY", "").strip()
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if origin.strip()
]
RATE_LIMIT_REQUESTS = _env_int("RATE_LIMIT_REQUESTS", 20)
RATE_LIMIT_WINDOW_SECONDS = _env_int("RATE_LIMIT_WINDOW_SECONDS", 60)
MAX_CONCURRENT_SCANS = max(1, _env_int("MAX_CONCURRENT_SCANS", 2))
ENABLE_DOCS = _env_flag("ENABLE_DOCS", "1")
MAX_HISTORY_LIMIT = 100

_SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
_STARTED_AT = time.time()


# ===========================================================================
# Rate limiting
# ===========================================================================


class SlidingWindowRateLimiter:
    """In-process sliding-window limiter.

    Sufficient for a single-worker deployment. Behind multiple workers or
    replicas this must move to Redis, otherwise each worker enforces its own
    independent budget.
    """

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = max(1, limit)
        self.window = max(1.0, float(window_seconds))
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> Tuple[bool, float]:
        """Return ``(allowed, retry_after_seconds)`` and record the hit."""

        now = time.monotonic()
        async with self._lock:
            bucket = self._hits.setdefault(key, deque())
            cutoff = now - self.window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.limit:
                retry_after = max(0.0, self.window - (now - bucket[0]))
                return False, round(retry_after, 2)

            bucket.append(now)

            # Opportunistic cleanup so idle clients do not accumulate forever.
            if len(self._hits) > 2048:
                for stale_key in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
                    self._hits.pop(stale_key, None)

            return True, 0.0


RATE_LIMITER = SlidingWindowRateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)


def client_identity(request: Request) -> str:
    """Best-effort client key for rate limiting."""

    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    real_ip = request.headers.get("x-real-ip", "")
    if real_ip:
        return real_ip.strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


async def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Enforce the shared secret when ``API_KEY`` is configured.

    With no key configured the API is open. That is convenient for local work
    and unacceptable for anything reachable from a network: set ``API_KEY`` (and
    front the service with TLS) before exposing it.
    """

    if not API_KEY:
        return
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid X-API-Key header is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


async def enforce_rate_limit(request: Request) -> None:
    allowed, retry_after = await RATE_LIMITER.check(client_identity(request))
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: {RATE_LIMIT_REQUESTS} requests per "
                f"{RATE_LIMIT_WINDOW_SECONDS}s. Retry in {retry_after:.0f}s."
            ),
            headers={"Retry-After": str(int(retry_after) + 1)},
        )


# ===========================================================================
# Application lifecycle
# ===========================================================================


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    LOGGER.info("ThreatLens %s starting up.", APP_VERSION)
    LOGGER.info("Database target: %s", safe_database_target())

    schema_ready = await run_in_threadpool(init_db)
    if not schema_ready:
        LOGGER.error(
            "Database is unavailable. Scans will still run, but history will not be persisted."
        )

    try:
        await start_browser()
    except BrowserUnavailable as exc:
        LOGGER.error("Chromium failed to start: %s", exc)

    LOGGER.info(
        "Engines - ai=%s (%s), threat_intel=%s, browser=%s",
        "on" if ai_enabled() else "off",
        f"{AI_PROVIDER_LABEL} / {AI_MODEL}",
        "on" if threat_intel_enabled() else "off",
        "ready" if browser_is_ready() else "unavailable",
    )
    LOGGER.info("Reputation engine: %s", reputation_status_detail())
    if not API_KEY:
        LOGGER.warning(
            "API_KEY is not set: /api/* endpoints are UNAUTHENTICATED. Acceptable for "
            "localhost development only - set API_KEY before exposing this service."
        )
    if not ai_enabled():
        LOGGER.warning(
            "%s is not set: the AI analyst pass will be skipped and scans will run on "
            "the rule engine plus threat intel. Free key: %s",
            AI_PRESET.key_env,
            AI_PRESET.signup_url or "n/a",
        )
    else:
        LOGGER.info("AI provider configuration: %s", ai_provider_info())
    if not threat_intel_enabled():
        LOGGER.warning("VIRUSTOTAL_API_KEY is not set: reputation lookups will be skipped.")

    try:
        yield
    finally:
        LOGGER.info("ThreatLens shutting down.")
        await shutdown_browser()
        await run_in_threadpool(dispose_engine)


app = FastAPI(
    title="ThreatLens API",
    description=(
        "AI-powered web threat detection and phishing analysis. Submit a URL and "
        "receive a fused threat score built from a sandboxed page capture, an LLM "
        "analyst pass and third-party reputation data."
    ),
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-Response-Time-Ms", "Retry-After"],
    max_age=600,
)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """Attach a request id, timing and hardening headers to every response."""

    request_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    started = time.perf_counter()

    response = await call_next(request)

    elapsed_ms = (time.perf_counter() - started) * 1000
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.1f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    # The API only ever emits JSON; a restrictive CSP costs nothing here.
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


# ===========================================================================
# Error handling
# ===========================================================================


def _request_id(request: Request) -> Optional[str]:
    return getattr(request.state, "request_id", None)


def _error_response(
    request: Request,
    status_code: int,
    error: str,
    detail: str,
    code: str,
    headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    payload = ErrorResponse(
        error=error,
        detail=detail[:1000],
        code=code,
        request_id=_request_id(request),
    )
    return JSONResponse(
        status_code=status_code,
        content=jsonable_encoder(payload),
        headers=headers or {},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Turn Pydantic errors (including SSRF rejections) into a clean message."""

    messages: List[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ()) if part != "body")
        message = str(error.get("msg", "invalid value"))
        for prefix in ("Value error, ", "Assertion failed, "):
            if message.startswith(prefix):
                message = message[len(prefix) :]
        messages.append(f"{location}: {message}" if location else message)

    detail = " | ".join(messages) or "The request payload failed validation."
    LOGGER.info("Rejected request: %s", detail)
    return _error_response(
        request,
        status.HTTP_422_UNPROCESSABLE_ENTITY,
        "Invalid request",
        detail,
        "validation_error",
    )


@app.exception_handler(UnsafeTargetError)
async def unsafe_target_handler(request: Request, exc: UnsafeTargetError) -> JSONResponse:
    LOGGER.warning("Blocked unsafe target: %s", exc)
    return _error_response(
        request,
        status.HTTP_400_BAD_REQUEST,
        "Target rejected",
        str(exc),
        "target_blocked",
    )


@app.exception_handler(ScraperError)
async def scraper_error_handler(request: Request, exc: ScraperError) -> JSONResponse:
    LOGGER.warning("Scrape failed (%s): %s", exc.code, exc)
    titles = {
        "scrape_timeout": "Target timed out",
        "target_blocked": "Target rejected",
        "navigation_failed": "Target unreachable",
        "browser_unavailable": "Analysis engine unavailable",
    }
    return _error_response(
        request,
        exc.http_status,
        titles.get(exc.code, "Analysis failed"),
        str(exc),
        exc.code,
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    code_map = {
        400: "bad_request",
        401: "unauthorized",
        404: "not_found",
        429: "rate_limited",
        503: "unavailable",
    }
    return _error_response(
        request,
        exc.status_code,
        "Request failed",
        str(exc.detail),
        code_map.get(exc.status_code, "http_error"),
        headers=dict(exc.headers or {}),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    LOGGER.exception("Unhandled error while processing %s: %s", request.url.path, exc)
    return _error_response(
        request,
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "Internal server error",
        "The analysis engine hit an unexpected error. The request id can be used to "
        "correlate this with the server logs.",
        "internal_error",
    )


# ===========================================================================
# Persistence helpers (run in the threadpool)
# ===========================================================================


def _persist_report(report: ScanReport, client_ip: Optional[str]) -> None:
    payload = report.model_dump(mode="json")
    # Keep the base64 image out of the JSON blob; it lives in its own column.
    payload.pop("screenshot_base64", None)

    row = ScanHistory(
        scan_id=report.scan_id,
        url=report.url[:2048],
        final_url=(report.final_url or report.url)[:2048],
        domain=report.domain[:253],
        registrable_domain=report.registrable_domain[:253],
        resolved_ips=report.resolved_ips,
        threat_score=report.threat_score,
        risk_level=report.risk_level.value,
        verdict=report.verdict[:64],
        summary=report.summary,
        recommended_action=report.recommended_action,
        risk_factors=payload.get("risk_factors"),
        ai_analysis=payload.get("ai_analysis"),
        virustotal=payload.get("virustotal"),
        response_headers=payload.get("headers"),
        page_metadata=payload.get("page_metadata"),
        raw_report=payload,
        screenshot_base64=report.screenshot_base64,
        screenshot_mime=report.screenshot_mime,
        dom_excerpt=report.dom_excerpt,
        page_title=(report.page_metadata.title or None),
        http_status=report.http_status,
        link_count=len(report.links),
        form_count=len(report.forms),
        duration_ms=report.duration_ms,
        engines_used=payload.get("engines"),
        client_ip=(client_ip or None),
    )
    with session_scope() as session:
        session.add(row)


def _fetch_history(limit: int, offset: int) -> ScanHistoryPage:
    with session_scope() as session:
        total = session.execute(select(func.count()).select_from(ScanHistory)).scalar_one()
        rows = (
            session.execute(
                select(ScanHistory)
                .order_by(ScanHistory.created_at.desc(), ScanHistory.id.desc())
                .limit(limit)
                .offset(offset)
            )
            .scalars()
            .all()
        )
        items: List[ScanHistoryItem] = [row.as_history_item() for row in rows]
    return ScanHistoryPage(items=items, total=int(total or 0), limit=limit, offset=offset)


def _fetch_report(scan_id: str) -> Optional[ScanReport]:
    with session_scope() as session:
        row = session.execute(
            select(ScanHistory).where(ScanHistory.scan_id == scan_id)
        ).scalar_one_or_none()
        if row is None:
            return None
        payload: Dict[str, Any] = dict(row.raw_report or {})
        if not payload:
            return None
        payload["screenshot_base64"] = row.screenshot_base64
    return ScanReport.model_validate(payload)


# ===========================================================================
# Orchestration
# ===========================================================================


async def _run_ai_pass(
    scrape: ScrapeResult,
    deep_analysis: bool,
    heuristic_factors: Sequence[RiskFactor],
    virustotal: VirusTotalReport,
) -> AIAnalysis:
    """Build the evidence document and run the LangChain analyst over it."""

    if not deep_analysis:
        return AIAnalysis(
            available=False,
            status="skipped",
            detail="deep_analysis was disabled for this request.",
            provider=AI_PROVIDER,
            ai_model=AI_MODEL,
        )

    evidence = build_evidence_payload(
        url=scrape.url,
        final_url=scrape.final_url,
        http_status=scrape.http_status,
        headers=scrape.headers,
        metadata=scrape.metadata,
        forms=scrape.forms,
        links=scrape.links,
        visible_text=scrape.visible_text,
        dom_excerpt=scrape.dom_excerpt,
        heuristic_factors=heuristic_factors,
        virustotal=virustotal,
    )

    try:
        return await analyze_with_llm(evidence)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # defence in depth: analyze_with_llm already guards
        LOGGER.warning("AI pass raised unexpectedly: %s", exc)
        return AIAnalysis(
            available=False,
            status="error",
            detail=str(exc)[:400],
            provider=AI_PROVIDER,
            ai_model=AI_MODEL,
        )


def _build_reputation_short_circuit_report(
    scan_id: str,
    url: str,
    host: str,
    base_domain: str,
    resolved_ips: Sequence[str],
    reputation: ReputationResult,
    started: float,
    request: Request,
) -> ScanReport:
    """Assemble a full ScanReport from a definitive blocklist hit alone.

    Used when the local feed already knows a domain is malicious, so the
    scraper, AI analyst and external intel are all skipped. The other engines
    are marked "skipped_reputation_hit" so the dashboard shows honestly that
    they did not run, rather than implying they were consulted.
    """

    final_score, risk_level, breakdown, all_factors = fuse_scores(
        heuristic_score=0,
        heuristic_factors=[],
        ai=AIAnalysis(
            available=False,
            status="skipped_reputation_hit",
            detail="Skipped: the domain matched the known-bad blocklist.",
            provider=AI_PROVIDER,
            ai_model=AI_MODEL,
        ),
        intel_score=0,
        intel_factors=[],
        reputation_score=reputation.score,
        reputation_factors=reputation.factors,
        reputation_classification=reputation.classification,
    )

    category_label = reputation.report.category or "malicious"
    is_pattern = reputation.report.match_type == "pattern"
    if is_pattern:
        verdict = "Matches a known malicious pattern"
        summary = (
            f"{base_domain} matches a known {category_label} domain pattern "
            f"('{reputation.report.matched_value}'). This host structure is strongly "
            "associated with malicious sites, so the verdict was issued from local "
            "threat intelligence without fetching the page. Treat with caution; a "
            "manual review can confirm."
        )
        recommended_action = (
            "Do not enter credentials. Block pending confirmation - the domain matches "
            "a phishing/scam naming pattern."
        )
    else:
        verdict = "Known malicious domain (blocklist)"
        summary = (
            f"{base_domain} is on the curated known-bad blocklist "
            f"(category: {category_label}, matched {reputation.report.match_type}). "
            "The verdict was issued instantly from local threat intelligence; the "
            "sandbox, AI analyst and external reputation lookup were skipped."
        )
        recommended_action = (
            "Block the domain at the proxy and DNS layer and treat any prior visits "
            "as compromised."
        )

    duration_ms = int((time.perf_counter() - started) * 1000)
    report = ScanReport(
        scan_id=scan_id,
        url=url,
        final_url=url,
        domain=host,
        registrable_domain=base_domain,
        resolved_ips=list(resolved_ips),
        threat_score=final_score,
        risk_level=risk_level,
        verdict=verdict[:64],
        summary=summary,
        recommended_action=recommended_action,
        risk_factors=all_factors,
        score_breakdown=breakdown,
        ai_analysis=AIAnalysis(
            available=False,
            status="skipped_reputation_hit",
            detail="Skipped: the domain matched the known-bad blocklist.",
            provider=AI_PROVIDER,
            ai_model=AI_MODEL,
        ),
        virustotal=VirusTotalReport(
            queried_domain=base_domain,
            status="skipped_reputation_hit",
            detail="Skipped: instant blocklist verdict.",
        ),
        reputation=reputation.report,
        screenshot_base64=None,
        screenshot_mime="image/jpeg",
        screenshot_bytes=0,
        headers={},
        security_headers={},
        http_status=None,
        tls_enabled=url.lower().startswith("https://"),
        page_metadata=PageMetadata(),
        forms=[],
        links=[],
        dom_excerpt="",
        engines=EngineStatus(
            reputation=reputation.report.status,
            scraper="skipped_reputation_hit",
            heuristics="skipped_reputation_hit",
            ai="skipped_reputation_hit",
            threat_intel="skipped_reputation_hit",
        ),
        duration_ms=duration_ms,
        scanned_at=datetime.now(timezone.utc),
    )

    try:
        # run_in_threadpool is async; this helper is sync, so persist inline.
        _persist_report(report, client_identity(request))
    except SQLAlchemyError as exc:
        LOGGER.error("[%s] Could not persist reputation short-circuit: %s", scan_id, getattr(exc, "orig", exc))

    LOGGER.info(
        "[%s] Verdict %s/100 (%s) for %s in %sms [reputation short-circuit]",
        scan_id,
        final_score,
        risk_level.value,
        base_domain,
        duration_ms,
    )
    return report


@app.post(
    "/api/scan",
    response_model=ScanReport,
    status_code=status.HTTP_200_OK,
    summary="Analyse a URL for phishing and web threats",
    responses={
        400: {"model": ErrorResponse, "description": "Target rejected by the SSRF policy"},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
        422: {"model": ErrorResponse, "description": "Malformed request payload"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        502: {"model": ErrorResponse, "description": "Target unreachable"},
        504: {"model": ErrorResponse, "description": "Target exceeded the time budget"},
    },
    dependencies=[Depends(require_api_key), Depends(enforce_rate_limit)],
)
async def scan_url(payload: URLRequest, request: Request) -> ScanReport:
    """Capture, analyse and score a single URL."""

    scan_id = str(uuid.uuid4())
    started = time.perf_counter()
    url = payload.url
    host = hostname_of(url)
    base_domain = registrable_domain(host)

    LOGGER.info("[%s] Scan requested for %s", scan_id, url)

    # --- Stage 1b: local reputation (curated blocklist / allowlist) -------
    # Runs FIRST - before DNS resolution and the scraper - so a known-bad or
    # known-pattern domain gets an instant, high-confidence verdict even if it
    # no longer resolves (phishing domains are often taken down within hours,
    # but the verdict is still the correct and useful answer). This is safe
    # because a short-circuit never fetches anything: no request leaves the box.
    reputation = check_reputation(url)
    if reputation.classification == "malicious" and reputation.report.match_type in {
        "exact_domain",
        "exact_host",
        "pattern",
    }:
        LOGGER.info(
            "[%s] Reputation short-circuit: %s is a known-bad %s (%s).",
            scan_id,
            reputation.report.matched_value,
            reputation.report.category,
            reputation.report.match_type,
        )
        return _build_reputation_short_circuit_report(
            scan_id=scan_id,
            url=url,
            host=host,
            base_domain=base_domain,
            resolved_ips=[],
            reputation=reputation,
            started=started,
            request=request,
        )

    # --- Stage 2: post-DNS SSRF verification -------------------------------
    # Only reached when reputation did not short-circuit. Structural validation
    # already ran in URLRequest; this closes the "public name, private answer"
    # hole (e.g. internal.example.com -> 127.0.0.1) before we fetch anything.
    try:
        target_port = urlparse(url).port
    except ValueError:
        target_port = None
    resolved_ips = await assert_host_is_public(host, target_port)
    LOGGER.info("[%s] %s resolves to %s", scan_id, host, resolved_ips)

    # --- Stage 3: sandboxed capture ---------------------------------------
    async with _SCAN_SEMAPHORE:
        scrape = await scrape_url(
            url,
            capture_screenshot=payload.include_screenshot,
            resolved_ips=resolved_ips,
        )

    scan_domain = scrape.domain or host
    scan_base_domain = registrable_domain(scan_domain) or base_domain

    # --- Stage 4: deterministic heuristics --------------------------------
    heuristic_score, heuristic_factors, impersonated = run_heuristics(
        url=scrape.final_url or url,
        headers=scrape.headers,
        metadata=scrape.metadata,
        forms=scrape.forms,
        links=scrape.links,
        visible_text=scrape.visible_text,
    )

    # --- Stage 5: reputation, then the LLM analyst -------------------------
    # The intel result is fetched first so the LLM can reason with it, which
    # measurably improves its calibration on freshly registered domains.
    if payload.check_threat_intel and threat_intel_enabled():
        virustotal = await lookup_virustotal(scan_domain, scrape.final_url or url)
    else:
        virustotal = VirusTotalReport(
            queried_domain=scan_domain,
            status="skipped" if threat_intel_enabled() else "not_configured",
            detail=(
                "Threat intel lookup disabled for this request."
                if threat_intel_enabled()
                else "VIRUSTOTAL_API_KEY is not set; reputation lookup skipped."
            ),
        )

    ai_result = await _run_ai_pass(
        scrape=scrape,
        deep_analysis=payload.deep_analysis,
        heuristic_factors=heuristic_factors,
        virustotal=virustotal,
    )

    intel_score, intel_factors = threat_intel_factors(virustotal)

    # --- Stage 6: fuse, describe, persist ---------------------------------
    final_score, risk_level, breakdown, all_factors = fuse_scores(
        heuristic_score=heuristic_score,
        heuristic_factors=heuristic_factors,
        ai=ai_result,
        intel_score=intel_score,
        intel_factors=intel_factors,
        reputation_score=reputation.score,
        reputation_factors=reputation.factors,
        reputation_classification=reputation.classification,
    )

    impersonated = impersonated or ai_result.brand_impersonated
    summary, recommended_action = build_summary(
        score=final_score,
        level=risk_level,
        factors=all_factors,
        ai=ai_result,
        impersonated=impersonated,
        domain=scan_domain,
    )

    duration_ms = int((time.perf_counter() - started) * 1000)
    engines = EngineStatus(
        reputation=reputation.report.status,
        scraper="ok",
        heuristics="ok",
        ai=ai_result.status,
        threat_intel=virustotal.status,
    )

    report = ScanReport(
        scan_id=scan_id,
        url=url,
        final_url=scrape.final_url or url,
        domain=scan_domain,
        registrable_domain=scan_base_domain,
        resolved_ips=scrape.resolved_ips,
        threat_score=final_score,
        risk_level=risk_level,
        verdict=(ai_result.verdict.strip() or risk_level_to_verdict(risk_level))[:64],
        summary=summary,
        recommended_action=recommended_action,
        risk_factors=all_factors,
        score_breakdown=breakdown,
        ai_analysis=ai_result,
        virustotal=virustotal,
        reputation=reputation.report,
        screenshot_base64=scrape.screenshot_base64,
        screenshot_mime=scrape.screenshot_mime,
        screenshot_bytes=scrape.screenshot_bytes,
        headers=scrape.headers,
        security_headers=scrape.security_header_matrix(),
        http_status=scrape.http_status,
        tls_enabled=scrape.tls_enabled,
        page_metadata=scrape.metadata,
        forms=scrape.forms,
        links=scrape.links[:80],
        dom_excerpt=scrape.dom_excerpt[:8000],
        engines=engines,
        duration_ms=duration_ms,
        scanned_at=datetime.now(timezone.utc),
    )

    try:
        await run_in_threadpool(_persist_report, report, client_identity(request))
    except SQLAlchemyError as exc:
        # History is valuable but never worth failing a completed analysis over.
        LOGGER.error("[%s] Could not persist scan: %s", scan_id, getattr(exc, "orig", exc))

    LOGGER.info(
        "[%s] Verdict %s/100 (%s) for %s in %sms [heuristic=%s ai=%s intel=%s]",
        scan_id,
        final_score,
        risk_level.value,
        scan_domain,
        duration_ms,
        heuristic_score,
        ai_result.threat_score if ai_result.available else "-",
        intel_score or "-",
    )
    return report


@app.get(
    "/api/scans",
    response_model=ScanHistoryPage,
    summary="List recent scans",
    dependencies=[Depends(require_api_key)],
)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=MAX_HISTORY_LIMIT),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> ScanHistoryPage:
    try:
        return await run_in_threadpool(_fetch_history, limit, offset)
    except SQLAlchemyError as exc:
        LOGGER.error("History query failed: %s", getattr(exc, "orig", exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan history is temporarily unavailable.",
        ) from exc


@app.get(
    "/api/scans/{scan_id}",
    response_model=ScanReport,
    summary="Retrieve a stored scan report",
    responses={404: {"model": ErrorResponse, "description": "Unknown scan id"}},
    dependencies=[Depends(require_api_key)],
)
async def get_scan(
    scan_id: str = Path(..., min_length=8, max_length=36, pattern=r"^[0-9a-fA-F-]{8,36}$"),
) -> ScanReport:
    try:
        report = await run_in_threadpool(_fetch_report, scan_id)
    except SQLAlchemyError as exc:
        LOGGER.error("Report lookup failed: %s", getattr(exc, "orig", exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan history is temporarily unavailable.",
        ) from exc

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No stored report for scan id '{scan_id}'.",
        )
    return report


@app.get("/api/config", response_model=EngineCapabilities, summary="Advertised engine capabilities")
async def get_config() -> EngineCapabilities:
    return EngineCapabilities(
        ai_enabled=ai_enabled(),
        ai_provider=AI_PROVIDER,
        ai_provider_label=AI_PROVIDER_LABEL,
        ai_model=AI_MODEL,
        # Surfaced so the dashboard can tell an operator exactly how to switch on
        # the AI engine instead of just showing a dead badge.
        ai_setup_url="" if ai_enabled() else AI_PRESET.signup_url,
        ai_key_env="" if ai_enabled() else AI_PRESET.key_env,
        threat_intel_enabled=threat_intel_enabled(),
        reputation_enabled=reputation_enabled(),
        reputation_blocklist_size=blocklist_size(),
        reputation_allowlist_size=allowlist_size(),
        auth_required=bool(API_KEY),
        max_concurrent_scans=MAX_CONCURRENT_SCANS,
        nav_timeout_ms=NAV_TIMEOUT_MS,
        rate_limit=f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW_SECONDS}s",
        version=APP_VERSION,
    )


@app.get("/api/health", response_model=HealthResponse, summary="Liveness and dependency health")
async def health() -> HealthResponse:
    db_status = await run_in_threadpool(database_status)
    browser_ready = browser_is_ready()
    overall = "ok" if (db_status.get("connected") and browser_ready) else "degraded"
    return HealthResponse(
        status=overall,
        version=APP_VERSION,
        uptime_seconds=round(time.time() - _STARTED_AT, 2),
        database=db_status,
        engines={
            "browser": browser_ready,
            "ai": ai_enabled(),
            "threat_intel": threat_intel_enabled(),
            "reputation": reputation_enabled(),
        },
    )


@app.get("/", summary="Service banner", include_in_schema=False)
async def root() -> Dict[str, Any]:
    return {
        "service": "ThreatLens API",
        "version": APP_VERSION,
        "docs": "/docs" if ENABLE_DOCS else "disabled",
        "endpoints": {
            "scan": "POST /api/scan",
            "history": "GET /api/scans",
            "report": "GET /api/scans/{scan_id}",
            "config": "GET /api/config",
            "health": "GET /api/health",
        },
    }
