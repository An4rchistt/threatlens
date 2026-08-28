"""Sandboxed page acquisition with Playwright.

Design rules for handling hostile URLs:

* **JavaScript is disabled.** Phishing kits are usually static credential
  harvesters, and executing attacker JS is the single largest risk in a
  crawler. Disabling it also removes fingerprinting, cryptominers and
  redirect loops.
* **Every request is filtered.** Navigation and sub-resources are re-checked
  against the SSRF policy, which closes the DNS-rebinding window left open by
  the pre-flight check in ``models.py``.
* **Hard timeouts at two levels.** A 10s navigation budget plus a total
  wall-clock budget enforced with ``asyncio.wait_for``, so a slow-loris target
  cannot pin a worker.
* **Nothing persists.** No storage state, no downloads, no service workers;
  the browser context is destroyed after every scan.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.async_api import (
    Browser,
    BrowserContext,
    Error as PlaywrightError,
    Page,
    Playwright,
    Request,
    Response,
    Route,
    TimeoutError as PlaywrightTimeoutError,
    async_playwright,
)

from models import (
    ALLOWED_PORTS,
    BLOCKED_HOST_SUFFIXES,
    BLOCKED_HOSTNAMES,
    FormSummary,
    LinkSummary,
    PageMetadata,
    coerce_ip_literal,
    hostname_of,
    is_public_ip,
    resolve_hostname,
    same_site,
)

LOGGER = logging.getLogger("threatlens.scraper")

_TRUTHY = {"1", "true", "yes", "on", "y"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        LOGGER.warning("Invalid integer for %s=%r - using %s", name, raw, default)
        return default


def _env_flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in _TRUTHY


# --- Tunables --------------------------------------------------------------
NAV_TIMEOUT_MS = _env_int("SCRAPER_NAV_TIMEOUT_MS", 10_000)
TOTAL_TIMEOUT_SECONDS = _env_int("SCRAPER_TOTAL_TIMEOUT_SECONDS", 30)
SCREENSHOT_TIMEOUT_MS = _env_int("SCRAPER_SCREENSHOT_TIMEOUT_MS", 15_000)
MAX_SCREENSHOT_BYTES = _env_int("SCRAPER_MAX_SCREENSHOT_BYTES", 3_500_000)
SCREENSHOT_QUALITY = max(20, min(_env_int("SCRAPER_SCREENSHOT_QUALITY", 68), 95))
MAX_DOM_CHARS = _env_int("SCRAPER_MAX_DOM_CHARS", 400_000)
DOM_EXCERPT_CHARS = _env_int("SCRAPER_DOM_EXCERPT_CHARS", 40_000)
MAX_TEXT_CHARS = _env_int("SCRAPER_MAX_TEXT_CHARS", 20_000)
MAX_LINKS = _env_int("SCRAPER_MAX_LINKS", 250)
MAX_FORMS = _env_int("SCRAPER_MAX_FORMS", 40)
MAX_SUBRESOURCE_REQUESTS = _env_int("SCRAPER_MAX_SUBRESOURCE_REQUESTS", 90)
VIEWPORT_WIDTH = _env_int("SCRAPER_VIEWPORT_WIDTH", 1366)
VIEWPORT_HEIGHT = _env_int("SCRAPER_VIEWPORT_HEIGHT", 900)
DISABLE_SANDBOX = _env_flag("SCRAPER_NO_SANDBOX", "1")
USER_AGENT = os.getenv(
    "SCRAPER_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
)

#: Resource types worth loading. Images and CSS are required for a screenshot
#: that looks like what a victim would see; everything else is dead weight or
#: an attack surface.
ALLOWED_RESOURCE_TYPES: Set[str] = {"document", "stylesheet", "image", "other"}
BLOCKED_RESOURCE_TYPES: Set[str] = {
    "media",
    "font",
    "websocket",
    "manifest",
    "eventsource",
    "texttrack",
    "xhr",
    "fetch",
    "script",
}

_OBFUSCATION_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("eval()", re.compile(r"\beval\s*\(", re.IGNORECASE)),
    ("atob()", re.compile(r"\batob\s*\(", re.IGNORECASE)),
    ("unescape()", re.compile(r"\bunescape\s*\(", re.IGNORECASE)),
    ("document.write()", re.compile(r"document\s*\.\s*write", re.IGNORECASE)),
    ("fromCharCode", re.compile(r"fromCharCode", re.IGNORECASE)),
    ("hex-escaped strings", re.compile(r"(?:\\x[0-9a-f]{2}){6,}", re.IGNORECASE)),
    ("long base64 blob", re.compile(r"[A-Za-z0-9+/]{240,}={0,2}")),
    ("punycode host", re.compile(r"xn--[a-z0-9-]+", re.IGNORECASE)),
    ("data: URI resource", re.compile(r"(?:src|href|action)\s*=\s*[\"']data:", re.IGNORECASE)),
    ("javascript: URI", re.compile(r"(?:href|action)\s*=\s*[\"']javascript:", re.IGNORECASE)),
    ("hidden iframe", re.compile(r"<iframe[^>]+(?:display\s*:\s*none|hidden|width\s*=\s*[\"']?0)", re.IGNORECASE)),
    ("password field present", re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.IGNORECASE)),
)

#: Brand names phishing kits impersonate most often. Detected in page text so
#: the analyzer can compare "who the page claims to be" against the real host.
BRAND_KEYWORDS: Tuple[str, ...] = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "onedrive",
    "google", "gmail", "amazon", "aws", "facebook", "meta", "instagram",
    "whatsapp", "netflix", "linkedin", "twitter", "telegram", "dropbox",
    "adobe", "docusign", "steam", "roblox", "spotify", "coinbase", "binance",
    "metamask", "kraken", "blockchain", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hsbc", "barclays", "santander", "lloyds", "natwest", "revolut",
    "monzo", "ing", "rabobank", "bbva", "unicredit", "dhl", "fedex", "ups",
    "usps", "royalmail", "irs", "hmrc", "sbi", "hdfc", "icici", "axis",
    "paytm", "phonepe", "netbanking", "linktree", "zoom", "webmail", "roundcube",
)

_CREDENTIAL_FIELD_HINTS: Tuple[str, ...] = (
    "pass", "pwd", "passwd", "password", "otp", "mfa", "2fa", "token",
    "pin", "cvv", "cvc", "card", "cardnumber", "ssn", "seed", "mnemonic",
    "secret", "recovery", "user", "username", "login", "email", "account",
)

_SECURITY_HEADERS: Tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


# ===========================================================================
# Exceptions
# ===========================================================================


class ScraperError(RuntimeError):
    """Base class for every recoverable scraping failure."""

    code = "scrape_failed"
    http_status = 502


class ScraperTimeout(ScraperError):
    code = "scrape_timeout"
    http_status = 504


class ScraperBlocked(ScraperError):
    """The target was refused for safety reasons (SSRF policy, bad scheme)."""

    code = "target_blocked"
    http_status = 400


class ScraperNavigationError(ScraperError):
    """DNS failure, TLS failure, connection refused, ERR_ABORTED, ..."""

    code = "navigation_failed"
    http_status = 502


class BrowserUnavailable(ScraperError):
    """Chromium could not be launched at all."""

    code = "browser_unavailable"
    http_status = 503


# ===========================================================================
# Result container
# ===========================================================================


@dataclass(slots=True)
class ScrapeResult:
    """Everything one sandboxed page visit produced."""

    url: str
    final_url: str
    http_status: Optional[int]
    headers: Dict[str, str]
    html: str
    dom_excerpt: str
    visible_text: str
    screenshot_base64: Optional[str]
    screenshot_mime: str
    screenshot_bytes: int
    metadata: PageMetadata
    forms: List[FormSummary]
    links: List[LinkSummary]
    redirect_chain: List[str] = field(default_factory=list)
    blocked_requests: List[str] = field(default_factory=list)
    resolved_ips: List[str] = field(default_factory=list)
    duration_ms: int = 0

    @property
    def domain(self) -> str:
        return hostname_of(self.final_url or self.url)

    @property
    def tls_enabled(self) -> bool:
        return (self.final_url or self.url).lower().startswith("https://")

    def security_header_matrix(self) -> Dict[str, bool]:
        present = {key.lower() for key in self.headers}
        return {header: header in present for header in _SECURITY_HEADERS}


# ===========================================================================
# Request-level SSRF guard
# ===========================================================================


class RequestGuard:
    """Per-scan allow/deny decisions for every request Chromium attempts."""

    def __init__(self, max_requests: int = MAX_SUBRESOURCE_REQUESTS) -> None:
        self._cache: Dict[str, bool] = {}
        self._lock = asyncio.Lock()
        self._max_requests = max_requests
        self.request_count = 0
        self.blocked: List[str] = []

    def _record_block(self, url: str, reason: str) -> None:
        entry = f"{reason}: {url[:180]}"
        if len(self.blocked) < 60 and entry not in self.blocked:
            self.blocked.append(entry)

    async def _host_is_public(self, host: str) -> bool:
        literal = coerce_ip_literal(host)
        if literal is not None:
            return is_public_ip(literal)

        if host in BLOCKED_HOSTNAMES:
            return False
        if any(host.endswith(suffix) for suffix in BLOCKED_HOST_SUFFIXES):
            return False
        if "." not in host:
            return False

        async with self._lock:
            cached = self._cache.get(host)
        if cached is not None:
            return cached

        allowed = True
        try:
            for address in await resolve_hostname(host, 443, timeout=3.0):
                try:
                    if not is_public_ip(ipaddress.ip_address(address)):
                        allowed = False
                        break
                except ValueError:
                    allowed = False
                    break
        except Exception:
            # Unresolvable hosts are harmless (the request cannot connect) but
            # are also pointless to forward.
            allowed = False

        async with self._lock:
            self._cache[host] = allowed
        return allowed

    async def handle(self, route: Route, request: Request) -> None:
        url = request.url
        resource_type = request.resource_type

        try:
            scheme = (urlparse(url).scheme or "").lower()
        except ValueError:
            await self._abort(route, url, "malformed URL")
            return

        if scheme in {"data", "blob"}:
            # Inline resources never touch the network; allow small ones through
            # so the screenshot keeps its inline logos.
            if len(url) <= 200_000:
                await self._continue(route)
            else:
                await self._abort(route, url, "oversized inline resource")
            return

        if scheme not in {"http", "https"}:
            await self._abort(route, url, f"blocked scheme '{scheme or 'none'}'")
            return

        if resource_type in BLOCKED_RESOURCE_TYPES:
            await self._abort(route, url, f"blocked resource type '{resource_type}'")
            return
        if resource_type not in ALLOWED_RESOURCE_TYPES:
            await self._abort(route, url, f"unexpected resource type '{resource_type}'")
            return

        parsed = urlparse(url)
        host = (parsed.hostname or "").strip(".").lower()
        if not host:
            await self._abort(route, url, "missing host")
            return

        try:
            port = parsed.port
        except ValueError:
            await self._abort(route, url, "invalid port")
            return
        if port is not None and port not in ALLOWED_PORTS:
            await self._abort(route, url, f"blocked port {port}")
            return

        if not await self._host_is_public(host):
            await self._abort(route, url, "non-public or unresolvable host")
            return

        async with self._lock:
            self.request_count += 1
            over_budget = self.request_count > self._max_requests
        if over_budget:
            await self._abort(route, url, "request budget exhausted")
            return

        await self._continue(route)

    async def _continue(self, route: Route) -> None:
        try:
            await route.continue_()
        except PlaywrightError:
            # The page navigated away or was closed mid-flight; nothing to do.
            pass

    async def _abort(self, route: Route, url: str, reason: str) -> None:
        self._record_block(url, reason)
        try:
            await route.abort("blockedbyclient")
        except PlaywrightError:
            pass


# ===========================================================================
# Browser lifecycle
# ===========================================================================


def _launch_args() -> List[str]:
    args = [
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-breakpad",
        "--disable-client-side-phishing-detection",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-domain-reliability",
        "--disable-features=AudioServiceOutOfProcess,TranslateUI,BackForwardCache,AcceptCHFrame",
        "--disable-hang-monitor",
        "--disable-ipc-flooding-protection",
        "--disable-notifications",
        "--disable-popup-blocking",
        "--disable-prompt-on-repost",
        "--disable-renderer-backgrounding",
        "--disable-sync",
        "--metrics-recording-only",
        "--mute-audio",
        "--no-default-browser-check",
        "--no-first-run",
        "--no-pings",
        "--no-zygote",
        "--password-store=basic",
        "--use-mock-keychain",
        "--hide-scrollbars",
    ]
    if DISABLE_SANDBOX:
        # Required inside a capability-dropped container: the setuid sandbox
        # helper cannot elevate. Compensating controls are documented at the top
        # of this module and in docker-compose.yml.
        args.extend(["--no-sandbox", "--disable-setuid-sandbox"])
    return args


class BrowserPool:
    """Single long-lived Chromium process shared by all scans.

    Launching Chromium costs ~400ms, so it is reused. Every scan still gets a
    brand-new incognito ``BrowserContext``, which is the isolation boundary that
    matters (separate cookie jar, cache and storage).
    """

    def __init__(self) -> None:
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        async with self._lock:
            await self._ensure_browser_locked()

    async def _ensure_browser_locked(self) -> Browser:
        if self._playwright is None:
            try:
                self._playwright = await async_playwright().start()
            except Exception as exc:  # pragma: no cover - environment failure
                raise BrowserUnavailable(f"Playwright could not start: {exc}") from exc

        if self._browser is None or not self._browser.is_connected():
            try:
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=_launch_args(),
                    chromium_sandbox=not DISABLE_SANDBOX,
                    handle_sigint=False,
                    handle_sigterm=False,
                    handle_sighup=False,
                    timeout=60_000,
                )
            except Exception as exc:
                raise BrowserUnavailable(f"Chromium could not be launched: {exc}") from exc
            LOGGER.info(
                "Chromium launched (version=%s, sandbox=%s).",
                self._browser.version,
                not DISABLE_SANDBOX,
            )
        return self._browser

    async def acquire(self) -> Browser:
        async with self._lock:
            return await self._ensure_browser_locked()

    async def stop(self) -> None:
        async with self._lock:
            if self._browser is not None:
                try:
                    await self._browser.close()
                except Exception as exc:  # pragma: no cover
                    LOGGER.warning("Error closing Chromium: %s", exc)
                self._browser = None
            if self._playwright is not None:
                try:
                    await self._playwright.stop()
                except Exception as exc:  # pragma: no cover
                    LOGGER.warning("Error stopping Playwright: %s", exc)
                self._playwright = None
        LOGGER.info("Browser pool shut down.")

    @property
    def is_ready(self) -> bool:
        return self._browser is not None and self._browser.is_connected()


BROWSER_POOL = BrowserPool()


# ===========================================================================
# Extraction helpers
# ===========================================================================


def _clean_text(value: Optional[str], limit: int = 400) -> str:
    if not value:
        return ""
    collapsed = re.sub(r"\s+", " ", str(value)).strip()
    return collapsed[:limit]


def _extract_visible_text(soup: BeautifulSoup) -> str:
    clone = BeautifulSoup(str(soup), "html.parser")
    for tag in clone(["script", "style", "noscript", "template", "svg", "head"]):
        tag.decompose()
    text = clone.get_text(separator=" ", strip=True)
    return re.sub(r"\s+", " ", text)[:MAX_TEXT_CHARS]


def _resolve(base: str, target: str) -> str:
    candidate = (target or "").strip()
    if not candidate:
        return ""
    lowered = candidate.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "sms:", "about:")):
        return candidate[:512]
    if lowered.startswith("data:"):
        return "data:[inline]"
    try:
        return urljoin(base, candidate)[:2048]
    except ValueError:
        return candidate[:2048]


def _extract_forms(soup: BeautifulSoup, base_url: str) -> List[FormSummary]:
    forms: List[FormSummary] = []
    for element in soup.find_all("form", limit=MAX_FORMS):
        raw_action = (element.get("action") or "").strip()
        resolved = _resolve(base_url, raw_action) if raw_action else base_url
        action_scheme = (urlparse(resolved).scheme or "").lower() if resolved else ""

        names: List[str] = []
        types: List[str] = []
        hidden = 0
        has_password = False
        has_email = False

        for control in element.find_all(["input", "select", "textarea"], limit=120):
            control_type = (control.get("type") or control.name or "").strip().lower()
            control_name = _clean_text(
                control.get("name") or control.get("id") or control.get("placeholder") or "",
                limit=64,
            )
            if control_type:
                types.append(control_type)
            if control_name:
                names.append(control_name)
            if control_type == "password":
                has_password = True
            if control_type == "email":
                has_email = True
            if control_type == "hidden":
                hidden += 1
            lowered_name = control_name.lower()
            if not has_password and any(hint in lowered_name for hint in ("pass", "pwd", "otp", "pin")):
                # Kits often use type="text" with a masking font to dodge scanners.
                has_password = True
            if not has_email and ("email" in lowered_name or "mail" in lowered_name):
                has_email = True

        cross_origin = bool(resolved) and resolved.startswith(("http://", "https://")) and not same_site(
            base_url, resolved
        )

        forms.append(
            FormSummary(
                action=raw_action[:2048],
                resolved_action=resolved,
                method=(element.get("method") or "get").strip().lower()[:10] or "get",
                input_count=len(types),
                input_names=names[:40],
                input_types=types[:40],
                has_password_field=has_password,
                has_email_field=has_email,
                has_hidden_fields=hidden > 0,
                hidden_field_count=hidden,
                is_cross_origin=cross_origin,
                action_scheme=action_scheme,
                action_is_insecure=action_scheme == "http",
                action_is_empty=not raw_action,
            )
        )
    return forms


def _extract_links(soup: BeautifulSoup, base_url: str) -> Tuple[List[LinkSummary], List[str]]:
    links: List[LinkSummary] = []
    seen: Set[str] = set()
    hosts: List[str] = []

    for anchor in soup.find_all("a", href=True, limit=MAX_LINKS * 4):
        resolved = _resolve(base_url, anchor.get("href", ""))
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        host = hostname_of(resolved)
        external = bool(host) and not same_site(base_url, resolved)
        if host and host not in hosts and len(hosts) < 60:
            hosts.append(host)
        links.append(
            LinkSummary(
                href=resolved,
                text=_clean_text(anchor.get_text(" ", strip=True), limit=160),
                is_external=external,
                host=host,
            )
        )
        if len(links) >= MAX_LINKS:
            break
    return links, hosts


def _detect_obfuscation(html: str) -> List[str]:
    markers: List[str] = []
    window = html[:MAX_DOM_CHARS]
    for label, pattern in _OBFUSCATION_PATTERNS:
        if pattern.search(window):
            markers.append(label)
    return markers


def _detect_brands(text: str, title: str) -> List[str]:
    haystack = f"{title} {text[:8000]}".lower()
    return [brand for brand in BRAND_KEYWORDS if brand in haystack][:12]


def _meta_content(soup: BeautifulSoup, **attrs: str) -> str:
    tag = soup.find("meta", attrs=attrs)
    if tag is None:
        return ""
    return _clean_text(tag.get("content", ""), limit=400)


def _build_metadata(
    soup: BeautifulSoup,
    html: str,
    visible_text: str,
    base_url: str,
    forms: List[FormSummary],
    links: List[LinkSummary],
    link_hosts: List[str],
    redirect_chain: List[str],
) -> PageMetadata:
    title = _clean_text(soup.title.string if soup.title and soup.title.string else "", limit=512)

    html_tag = soup.find("html")
    language = _clean_text(html_tag.get("lang", "") if html_tag else "", limit=32)

    favicon = ""
    for rel in ("icon", "shortcut icon", "apple-touch-icon"):
        icon = soup.find("link", rel=lambda value, target=rel: bool(value) and target in " ".join(
            value if isinstance(value, list) else [value]
        ).lower())
        if icon is not None and icon.get("href"):
            favicon = _resolve(base_url, icon.get("href", ""))
            break

    canonical = ""
    canonical_tag = soup.find("link", rel=lambda value: bool(value) and "canonical" in " ".join(
        value if isinstance(value, list) else [value]
    ).lower())
    if canonical_tag is not None and canonical_tag.get("href"):
        canonical = _resolve(base_url, canonical_tag.get("href", ""))

    meta_refresh = ""
    refresh_tag = soup.find(
        "meta", attrs={"http-equiv": lambda value: bool(value) and value.lower() == "refresh"}
    )
    if refresh_tag is not None:
        meta_refresh = _clean_text(refresh_tag.get("content", ""), limit=512)

    iframes = [
        _resolve(base_url, frame.get("src", ""))
        for frame in soup.find_all("iframe", limit=40)
        if frame.get("src")
    ]

    script_hosts: List[str] = []
    script_tags = soup.find_all("script", limit=200)
    for script in script_tags:
        src = script.get("src")
        if not src:
            continue
        host = hostname_of(_resolve(base_url, src))
        if host and host not in script_hosts and not same_site(base_url, f"https://{host}"):
            script_hosts.append(host)

    hidden_inputs = sum(
        1
        for control in soup.find_all("input", limit=400)
        if (control.get("type") or "").strip().lower() == "hidden"
    )
    password_fields = sum(1 for form in forms if form.has_password_field)

    return PageMetadata(
        title=title,
        description=(
            _meta_content(soup, name="description")
            or _meta_content(soup, property="og:description")
        ),
        language=language,
        generator=_meta_content(soup, name="generator"),
        favicon=favicon,
        meta_refresh=meta_refresh,
        canonical_url=canonical,
        text_length=len(visible_text),
        dom_length=len(html),
        link_count=len(links),
        external_link_count=sum(1 for link in links if link.is_external),
        unique_link_hosts=link_hosts[:40],
        form_count=len(forms),
        password_field_count=password_fields,
        hidden_input_count=hidden_inputs,
        iframe_count=len(iframes),
        iframe_sources=iframes[:20],
        script_count=len(script_tags),
        external_script_hosts=script_hosts[:20],
        image_count=len(soup.find_all("img", limit=500)),
        redirect_chain=redirect_chain[:12],
        obfuscation_markers=_detect_obfuscation(html),
        brand_keywords=_detect_brands(visible_text, title),
    )


def _normalise_headers(raw: Dict[str, str]) -> Dict[str, str]:
    """Lowercase header names and truncate values; drop noisy cookie payloads."""

    cleaned: Dict[str, str] = {}
    for key, value in (raw or {}).items():
        name = str(key).strip().lower()
        if not name:
            continue
        if name == "set-cookie":
            # Keep the attributes (Secure/HttpOnly matter) but not the value.
            parts = str(value).split(";")
            attributes = ";".join(part.strip() for part in parts[1:])[:300]
            cleaned[name] = f"[redacted]; {attributes}" if attributes else "[redacted]"
            continue
        cleaned[name] = _clean_text(value, limit=512)
        if len(cleaned) >= 60:
            break
    return cleaned


# ===========================================================================
# Public API
# ===========================================================================


async def _capture_screenshot(page: Page) -> Tuple[Optional[str], str, int]:
    """Full-page JPEG, degraded to viewport-only if it exceeds the size cap."""

    try:
        raw = await page.screenshot(
            full_page=True,
            type="jpeg",
            quality=SCREENSHOT_QUALITY,
            timeout=SCREENSHOT_TIMEOUT_MS,
            animations="disabled",
            caret="hide",
            scale="css",
        )
    except (PlaywrightTimeoutError, PlaywrightError) as exc:
        LOGGER.warning("Full-page screenshot failed (%s); retrying viewport only.", exc)
        try:
            raw = await page.screenshot(
                full_page=False,
                type="jpeg",
                quality=SCREENSHOT_QUALITY,
                timeout=8_000,
            )
        except (PlaywrightTimeoutError, PlaywrightError) as inner:
            LOGGER.warning("Viewport screenshot also failed: %s", inner)
            return None, "image/jpeg", 0

    if len(raw) > MAX_SCREENSHOT_BYTES:
        LOGGER.info(
            "Screenshot too large (%s bytes > %s); re-capturing viewport only.",
            len(raw),
            MAX_SCREENSHOT_BYTES,
        )
        try:
            raw = await page.screenshot(
                full_page=False,
                type="jpeg",
                quality=max(30, SCREENSHOT_QUALITY - 20),
                timeout=8_000,
            )
        except (PlaywrightTimeoutError, PlaywrightError):
            raw = raw[:MAX_SCREENSHOT_BYTES]

    return base64.b64encode(raw).decode("ascii"), "image/jpeg", len(raw)


async def _scrape_once(
    url: str,
    capture_screenshot: bool,
    resolved_ips: List[str],
) -> ScrapeResult:
    started = time.perf_counter()
    browser = await BROWSER_POOL.acquire()

    guard = RequestGuard()
    redirect_chain: List[str] = []
    context: Optional[BrowserContext] = None
    page: Optional[Page] = None

    try:
        context = await browser.new_context(
            java_script_enabled=False,          # hard requirement: never run target JS
            user_agent=USER_AGENT,
            viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
            device_scale_factor=1,
            locale="en-US",
            timezone_id="UTC",
            ignore_https_errors=True,           # analyse the page even on a bad cert
            bypass_csp=False,
            accept_downloads=False,
            service_workers="block",
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "Sec-GPC": "1",
                "DNT": "1",
            },
        )
        context.set_default_timeout(NAV_TIMEOUT_MS)
        context.set_default_navigation_timeout(NAV_TIMEOUT_MS)
        await context.route("**/*", guard.handle)

        page = await context.new_page()
        page.on(
            "response",
            lambda response: redirect_chain.append(response.url)
            if 300 <= response.status < 400 and len(redirect_chain) < 12
            else None,
        )

        try:
            response: Optional[Response] = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=NAV_TIMEOUT_MS,
                referer=None,
            )
        except PlaywrightTimeoutError as exc:
            raise ScraperTimeout(
                f"Navigation exceeded the {NAV_TIMEOUT_MS / 1000:.0f}s budget."
            ) from exc
        except PlaywrightError as exc:
            message = str(exc)
            if "net::ERR_BLOCKED_BY_CLIENT" in message:
                raise ScraperBlocked(
                    "Navigation was blocked by the SSRF policy: the target redirected "
                    "to a private, reserved or unresolvable address."
                ) from exc
            first_line = message.strip().splitlines()[0][:300]
            raise ScraperNavigationError(f"Navigation failed: {first_line}") from exc

        # Give late CSS/images a brief, bounded chance to settle. JS is off, so
        # "networkidle" resolves fast or not at all - either way we move on.
        try:
            await page.wait_for_load_state("load", timeout=min(4_000, NAV_TIMEOUT_MS))
        except (PlaywrightTimeoutError, PlaywrightError):
            pass

        http_status = response.status if response is not None else None
        headers = _normalise_headers(await response.all_headers()) if response is not None else {}
        final_url = page.url or url

        try:
            html = await page.content()
        except PlaywrightError as exc:
            raise ScraperError(f"Could not read the page DOM: {str(exc)[:200]}") from exc

        if len(html) > MAX_DOM_CHARS:
            LOGGER.info("Truncating DOM from %s to %s characters.", len(html), MAX_DOM_CHARS)
            html = html[:MAX_DOM_CHARS]

        screenshot_b64: Optional[str] = None
        screenshot_mime = "image/jpeg"
        screenshot_bytes = 0
        if capture_screenshot:
            screenshot_b64, screenshot_mime, screenshot_bytes = await _capture_screenshot(page)

        soup = BeautifulSoup(html, "html.parser")
        visible_text = _extract_visible_text(soup)
        forms = _extract_forms(soup, final_url)
        links, link_hosts = _extract_links(soup, final_url)
        metadata = _build_metadata(
            soup=soup,
            html=html,
            visible_text=visible_text,
            base_url=final_url,
            forms=forms,
            links=links,
            link_hosts=link_hosts,
            redirect_chain=redirect_chain,
        )

        duration_ms = int((time.perf_counter() - started) * 1000)
        LOGGER.info(
            "Scraped %s -> status=%s dom=%s links=%s forms=%s blocked=%s in %sms",
            url,
            http_status,
            len(html),
            len(links),
            len(forms),
            len(guard.blocked),
            duration_ms,
        )

        return ScrapeResult(
            url=url,
            final_url=final_url,
            http_status=http_status,
            headers=headers,
            html=html,
            dom_excerpt=html[:DOM_EXCERPT_CHARS],
            visible_text=visible_text,
            screenshot_base64=screenshot_b64,
            screenshot_mime=screenshot_mime,
            screenshot_bytes=screenshot_bytes,
            metadata=metadata,
            forms=forms,
            links=links,
            redirect_chain=redirect_chain[:12],
            blocked_requests=guard.blocked,
            resolved_ips=resolved_ips,
            duration_ms=duration_ms,
        )
    finally:
        if page is not None:
            try:
                await page.close()
            except Exception:  # pragma: no cover - best-effort teardown
                pass
        if context is not None:
            try:
                await context.close()
            except Exception:  # pragma: no cover
                pass


async def scrape_url(
    url: str,
    capture_screenshot: bool = True,
    resolved_ips: Optional[List[str]] = None,
    total_timeout: Optional[float] = None,
) -> ScrapeResult:
    """Fetch ``url`` in a disposable, JS-free browser context.

    Parameters
    ----------
    url:
        Pre-validated absolute http(s) URL (see ``models.validate_and_normalise_url``).
    capture_screenshot:
        Capture a full-page JPEG and return it base64-encoded.
    resolved_ips:
        Addresses the pre-flight SSRF check already resolved, echoed into the
        report so analysts see where the name pointed at scan time.
    total_timeout:
        Wall-clock ceiling for the whole visit, including screenshotting.

    Raises
    ------
    ScraperTimeout, ScraperBlocked, ScraperNavigationError, BrowserUnavailable,
    ScraperError
    """

    budget = float(total_timeout or TOTAL_TIMEOUT_SECONDS)
    try:
        return await asyncio.wait_for(
            _scrape_once(url, capture_screenshot, list(resolved_ips or [])),
            timeout=budget,
        )
    except asyncio.TimeoutError as exc:
        raise ScraperTimeout(
            f"Analysis of the target exceeded the {budget:.0f}s wall-clock budget."
        ) from exc
    except ScraperError:
        raise
    except PlaywrightTimeoutError as exc:
        raise ScraperTimeout(f"Browser operation timed out: {str(exc)[:200]}") from exc
    except PlaywrightError as exc:
        raise ScraperError(f"Browser error: {str(exc)[:200]}") from exc


async def start_browser() -> None:
    """Warm the shared Chromium instance during application startup."""

    await BROWSER_POOL.start()


async def shutdown_browser() -> None:
    """Tear down Chromium and Playwright during application shutdown."""

    await BROWSER_POOL.stop()


def browser_is_ready() -> bool:
    return BROWSER_POOL.is_ready
