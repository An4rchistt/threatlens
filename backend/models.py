"""Domain models for ThreatLens.

Contents
--------
1. URL safety utilities  - SSRF defence used before a single packet is sent.
2. Domain utilities      - registrable-domain extraction (no network calls).
3. SQLAlchemy ORM model  - ``ScanHistory``.
4. Pydantic schemas      - request/response contracts for the FastAPI layer.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from database import Base

LOGGER = logging.getLogger("threatlens.models")

# JSONB on Postgres, plain JSON elsewhere (e.g. the sqlite dev fallback).
JSONColumn = JSON().with_variant(JSONB(), "postgresql")


# ===========================================================================
# 1. URL SAFETY / SSRF DEFENCE
# ===========================================================================

MAX_URL_LENGTH = 2048

ALLOWED_SCHEMES: Set[str] = {"http", "https"}

#: Ports the scanner is willing to dial. Everything else (SMB, Redis, Postgres,
#: SSH, Docker API, Kubelet, ...) is refused outright.
ALLOWED_PORTS: Set[int] = {80, 443, 8080, 8443, 8000, 3000}

#: Host names that always resolve to something local or to a cloud metadata
#: endpoint. Matched case-insensitively against the full host.
BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "host.docker.internal",
    "gateway.docker.internal",
    "docker.for.mac.localhost",
    "docker.for.win.localhost",
}

#: Suffixes reserved for private/internal name spaces (RFC 6761 / RFC 8375).
BLOCKED_HOST_SUFFIXES: Tuple[str, ...] = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".intra",
    ".corp",
    ".home",
    ".home.arpa",
    ".lan",
    ".private",
    ".test",
    ".example",
    ".invalid",
    ".onion",
    ".svc",
    ".cluster.local",
)

#: Extra CIDRs that are technically "global" but must never be scanned.
#: NAT64 (64:ff9b::/96) is deliberately NOT listed here: it embeds a real IPv4
#: destination in its low 32 bits, and DNS64 environments (including Docker
#: Desktop's Linux VM) legitimately return it for public hosts. It is handled
#: below by decoding and validating the embedded IPv4 instead of a blanket block.
EXTRA_BLOCKED_NETWORKS: Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("100.64.0.0/10"),      # RFC 6598 carrier NAT
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),      # benchmarking
    ipaddress.ip_network("192.88.99.0/24"),     # deprecated 6to4 relay anycast
    ipaddress.ip_network("100::/64"),           # IPv6 discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # documentation
)

#: NAT64 / DNS64 well-known prefix (RFC 6052). Addresses in this range wrap an
#: IPv4 destination in their final 32 bits.
NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _nat64_embedded_ipv4(
    address: ipaddress.IPv6Address,
) -> Optional[ipaddress.IPv4Address]:
    """Return the IPv4 address a NAT64 address maps to, or None."""

    if address not in NAT64_PREFIX:
        return None
    try:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    except (ipaddress.AddressValueError, ValueError):
        return None

_HOST_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_NUMERIC_HOST_RE = re.compile(r"^(0x[0-9a-f]+|0[0-7]*|[1-9][0-9]*)$", re.IGNORECASE)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x20\x7f]")


class UnsafeTargetError(ValueError):
    """Raised when a URL (or the address it resolves to) must not be fetched."""


def _decode_numeric_component(component: str) -> Optional[int]:
    """Decode one host component written in hex, octal or decimal."""

    text = component.strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if len(text) > 1 and text.startswith("0"):
            return int(text, 8)
        return int(text, 10)
    except ValueError:
        return None


def coerce_ip_literal(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return the IP a host string encodes, covering obfuscated notations.

    Handles the classic SSRF bypasses that ``ipaddress`` alone rejects, e.g.
    ``2130706433``, ``0x7f000001``, ``0177.0.0.1`` and ``127.1`` - all of which
    Chromium happily resolves to loopback.
    """

    candidate = host.strip().strip("[]")
    if not candidate:
        return None

    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass

    parts = candidate.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    if not all(_NUMERIC_HOST_RE.match(part or "") for part in parts):
        return None

    decoded: List[int] = []
    for part in parts:
        value = _decode_numeric_component(part)
        if value is None or value < 0:
            return None
        decoded.append(value)

    # inet_aton semantics: the final component absorbs the remaining octets.
    if len(decoded) == 1:
        packed = decoded[0]
    else:
        leading, last = decoded[:-1], decoded[-1]
        if any(octet > 255 for octet in leading):
            return None
        remaining_octets = 4 - len(leading)
        if last >= 1 << (8 * remaining_octets):
            return None
        packed = last
        for index, octet in enumerate(reversed(leading)):
            packed |= octet << (8 * (remaining_octets + index))

    if packed > 0xFFFFFFFF:
        return None
    try:
        return ipaddress.IPv4Address(packed)
    except ValueError:
        return None


def is_public_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable addresses safe to scan."""

    # NAT64 must be resolved FIRST. Python's ipaddress classifies the
    # 64:ff9b::/96 prefix as `is_reserved`, so the generic checks below would
    # reject it outright - but DNS64 environments (Docker Desktop's Linux VM
    # included) return NAT64 addresses for ordinary public hosts like
    # github.com. The security decision is made purely on the embedded IPv4:
    # public IPv4 -> allowed, private/loopback/metadata IPv4 -> blocked.
    if isinstance(address, ipaddress.IPv6Address):
        nat64_v4 = _nat64_embedded_ipv4(address)
        if nat64_v4 is not None:
            return is_public_ip(nat64_v4)

    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    if not address.is_global:
        return False

    for network in EXTRA_BLOCKED_NETWORKS:
        if address.version == network.version and address in network:
            return False

    if isinstance(address, ipaddress.IPv6Address):
        # An attacker can smuggle a private IPv4 inside an IPv6 wrapper, so any
        # embedded IPv4 must itself be public.
        for embedded in (address.ipv4_mapped, address.sixtofour):
            if embedded is not None and not is_public_ip(embedded):
                return False
        teredo = address.teredo
        if teredo is not None and any(not is_public_ip(part) for part in teredo):
            return False

    return True


def _assert_hostname_allowed(host: str) -> None:
    """Structural host checks: reserved names, internal suffixes, bad labels."""

    if host in BLOCKED_HOSTNAMES:
        raise UnsafeTargetError(
            f"Refusing to scan reserved host name '{host}'. "
            "Internal and loopback targets are blocked."
        )
    for suffix in BLOCKED_HOST_SUFFIXES:
        if host.endswith(suffix):
            raise UnsafeTargetError(
                f"Refusing to scan '{host}': '{suffix}' is a private/reserved name space."
            )
    if "." not in host:
        raise UnsafeTargetError(
            f"Refusing to scan single-label host '{host}'. "
            "Provide a fully-qualified public domain."
        )
    if host.endswith("-") or host.startswith("-"):
        raise UnsafeTargetError(f"Malformed host name '{host}'.")
    if len(host) > 253:
        raise UnsafeTargetError("Host name exceeds the 253 character DNS limit.")
    for label in host.split("."):
        if not label:
            raise UnsafeTargetError(f"Malformed host name '{host}' (empty DNS label).")
        if not _HOST_LABEL_RE.match(label):
            raise UnsafeTargetError(
                f"Malformed host name '{host}': invalid DNS label '{label}'."
            )


def validate_and_normalise_url(raw: str) -> str:
    """Validate a user-supplied URL and return a canonical, safe form.

    Raises :class:`UnsafeTargetError` (a ``ValueError`` subclass, so Pydantic
    reports it as a 422) for anything that could be used to reach into the
    infrastructure the scanner runs on.
    """

    if not isinstance(raw, str):
        raise UnsafeTargetError("URL must be a string.")

    candidate = _CONTROL_CHARS_RE.sub("", raw.strip().strip("'\""))
    if not candidate:
        raise UnsafeTargetError("URL must not be empty.")
    if len(candidate) > MAX_URL_LENGTH:
        raise UnsafeTargetError(f"URL exceeds the {MAX_URL_LENGTH} character limit.")
    # Backslashes inside the authority are parsed inconsistently across browsers
    # and are a well-known origin-confusion trick (http://evil.com\@good.com).
    authority_fragment = candidate.split("//", 1)[-1].split("/", 1)[0] if "//" in candidate else ""
    if "\\" in authority_fragment:
        raise UnsafeTargetError("Backslashes are not allowed in the URL authority.")

    if "://" not in candidate:
        candidate = "https:" + candidate if candidate.startswith("//") else "https://" + candidate

    try:
        parsed = urlparse(candidate)
    except ValueError as exc:
        raise UnsafeTargetError(f"URL could not be parsed: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError(
            f"Unsupported scheme '{scheme or 'none'}'. Only http:// and https:// are accepted."
        )

    if "@" in parsed.netloc:
        raise UnsafeTargetError(
            "Embedded credentials are not allowed; they are a common phishing "
            "and SSRF obfuscation technique."
        )

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeTargetError("URL must include a host name.")

    hostname = hostname.strip().strip(".").lower()
    if not hostname:
        raise UnsafeTargetError("URL must include a host name.")

    # Internationalised domains are converted to punycode so downstream
    # comparisons operate on a single canonical representation.
    if any(ord(char) > 127 for char in hostname):
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError) as exc:
            raise UnsafeTargetError(
                "Host name contains characters that cannot be encoded as IDNA/punycode."
            ) from exc

    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTargetError(f"Invalid port in URL: {exc}") from exc

    if port is not None and port not in ALLOWED_PORTS:
        allowed = ", ".join(str(item) for item in sorted(ALLOWED_PORTS))
        raise UnsafeTargetError(f"Port {port} is not permitted. Allowed ports: {allowed}.")

    literal_ip = coerce_ip_literal(hostname)
    if literal_ip is not None:
        if not is_public_ip(literal_ip):
            raise UnsafeTargetError(
                f"Refusing to scan non-public address {literal_ip}. Loopback, private, "
                "link-local, metadata and reserved ranges are blocked."
            )
        hostname = str(literal_ip)
    else:
        _assert_hostname_allowed(hostname)

    if literal_ip is not None and literal_ip.version == 6:
        netloc = f"[{hostname}]"
    else:
        netloc = hostname
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{netloc}:{port}"

    path = parsed.path or "/"
    # Fragments never reach the server; drop them so identical targets hash alike.
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


async def resolve_hostname(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
) -> List[str]:
    """Resolve ``hostname`` to every A/AAAA record, without blocking the loop."""

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP),
            timeout=timeout,
        )
    except asyncio.TimeoutError as exc:
        raise UnsafeTargetError(
            f"DNS resolution for '{hostname}' timed out after {timeout:.0f}s."
        ) from exc
    except socket.gaierror as exc:
        raise UnsafeTargetError(
            f"Host '{hostname}' could not be resolved ({exc.strerror or exc})."
        ) from exc

    addresses: List[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str) and sockaddr[0] not in addresses:
            addresses.append(sockaddr[0])
    if not addresses:
        raise UnsafeTargetError(f"Host '{hostname}' returned no usable DNS records.")
    return addresses


async def assert_host_is_public(
    hostname: str,
    port: Optional[int] = None,
    timeout: float = 5.0,
) -> List[str]:
    """Resolve a host and refuse it if *any* answer points somewhere internal.

    Structural validation alone is not enough: ``internal.attacker.com`` can
    legitimately resolve to ``127.0.0.1``. Checking every returned record closes
    that hole (DNS rebinding between this check and the fetch remains a
    theoretical residual risk, which is why the scraper re-checks each
    sub-resource request as well).
    """

    literal = coerce_ip_literal(hostname)
    if literal is not None:
        if not is_public_ip(literal):
            raise UnsafeTargetError(f"Refusing to scan non-public address {literal}.")
        return [str(literal)]

    addresses = await resolve_hostname(hostname, port or 443, timeout=timeout)
    for address in addresses:
        try:
            parsed_ip = ipaddress.ip_address(address)
        except ValueError:
            raise UnsafeTargetError(f"DNS returned an unparsable address: {address!r}")
        if not is_public_ip(parsed_ip):
            raise UnsafeTargetError(
                f"Host '{hostname}' resolves to the non-public address {address}. "
                "Blocked to prevent server-side request forgery."
            )
    return addresses


# ===========================================================================
# 2. DOMAIN UTILITIES
# ===========================================================================

#: Two-plus-label public suffixes plus widely abused free-hosting suffixes.
#: Keeping this in-process avoids a network fetch of the full PSL on startup.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        # --- ccTLD second levels -------------------------------------------
        "ac.at", "co.at", "gv.at", "or.at",
        "asn.au", "com.au", "edu.au", "gov.au", "id.au", "net.au", "org.au",
        "com.ar", "edu.ar", "gob.ar", "net.ar", "org.ar",
        "com.bd", "edu.bd", "gov.bd", "net.bd", "org.bd",
        "com.bo", "com.br", "edu.br", "gov.br", "net.br", "org.br",
        "ac.cn", "com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn",
        "com.co", "edu.co", "gov.co", "net.co", "org.co",
        "com.cu", "com.cy", "com.do", "com.ec", "com.eg",
        "com.es", "edu.es", "gob.es", "nom.es", "org.es",
        "com.gt", "com.hr",
        "com.hk", "edu.hk", "gov.hk", "idv.hk", "net.hk", "org.hk",
        "ac.id", "biz.id", "co.id", "go.id", "my.id", "or.id", "sch.id", "web.id",
        "ac.il", "co.il", "gov.il", "net.il", "org.il",
        "ac.in", "co.in", "edu.in", "firm.in", "gen.in", "gov.in", "ind.in",
        "mil.in", "net.in", "nic.in", "org.in", "res.in",
        "com.it", "edu.it", "gov.it",
        "ac.jp", "co.jp", "go.jp", "lg.jp", "ne.jp", "or.jp",
        "ac.ke", "co.ke", "go.ke", "ne.ke", "or.ke",
        "co.kr", "go.kr", "ne.kr", "or.kr", "pe.kr", "re.kr",
        "com.kw", "com.lb", "com.lk", "com.lt", "com.lv",
        "com.ma", "co.ma", "com.mt", "com.mx", "edu.mx", "gob.mx", "net.mx", "org.mx",
        "com.my", "edu.my", "gov.my", "net.my", "org.my",
        "co.mz", "com.ng", "edu.ng", "gov.ng", "net.ng", "org.ng",
        "com.ni",
        "ac.nz", "co.nz", "govt.nz", "net.nz", "org.nz", "school.nz",
        "com.om", "com.pa", "com.pe",
        "com.ph", "edu.ph", "gov.ph", "net.ph", "org.ph",
        "com.pk", "edu.pk", "gov.pk", "net.pk", "org.pk",
        "com.pl", "edu.pl", "gov.pl", "net.pl", "org.pl", "waw.pl",
        "com.pt", "edu.pt", "gov.pt", "org.pt",
        "com.py", "com.qa", "com.ro",
        "com.ru", "msk.ru", "net.ru", "org.ru", "pp.ru", "spb.ru",
        "com.sa", "com.sv",
        "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
        "ac.th", "co.th", "go.th", "in.th", "or.th",
        "com.tr", "edu.tr", "gov.tr", "net.tr", "org.tr",
        "com.tw", "edu.tw", "gov.tw", "net.tw", "org.tw",
        "co.tz",
        "com.ua", "in.ua", "kiev.ua", "net.ua", "org.ua",
        "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "mod.uk", "net.uk",
        "nhs.uk", "org.uk", "plc.uk", "police.uk", "sch.uk",
        "co.ug", "com.uy", "com.ve",
        "com.vn", "edu.vn", "gov.vn", "net.vn", "org.vn",
        "ac.za", "co.za", "gov.za", "net.za", "org.za", "web.za",
        "co.zw",
        # --- Free hosting / PaaS (frequently abused for phishing kits) -----
        "000webhostapp.com", "amplifyapp.com", "appspot.com", "azurewebsites.net",
        "blogspot.com", "cloudfront.net", "codeberg.page", "duckdns.org",
        "firebaseapp.com", "fly.dev", "framer.website", "gitbook.io",
        "github.io", "gitlab.io", "glitch.me", "herokuapp.com", "hostingersite.com",
        "myshopify.com", "narod.ru", "neocities.org", "netlify.app",
        "ngrok-free.app", "ngrok.io", "notion.site", "onrender.com",
        "pages.dev", "r2.dev", "repl.co", "replit.app", "s3.amazonaws.com",
        "sharepoint.com", "sites.google.com", "squarespace.com", "surge.sh",
        "translate.goog", "trycloudflare.com", "ucoz.ru", "vercel.app",
        "web.app", "webflow.io", "weeblysite.com", "wixsite.com",
        "wordpress.com", "workers.dev", "yolasite.com",
    }
)

#: Suffixes that are shared hosting: the registrable domain belongs to the
#: platform, not to the person publishing the page.
SHARED_HOSTING_SUFFIXES: frozenset[str] = frozenset(
    {
        "000webhostapp.com", "amplifyapp.com", "appspot.com", "azurewebsites.net",
        "blogspot.com", "duckdns.org", "firebaseapp.com", "fly.dev",
        "framer.website", "gitbook.io", "github.io", "gitlab.io", "glitch.me",
        "herokuapp.com", "hostingersite.com", "myshopify.com", "narod.ru",
        "neocities.org", "netlify.app", "ngrok-free.app", "ngrok.io",
        "notion.site", "onrender.com", "pages.dev", "r2.dev", "repl.co",
        "replit.app", "sites.google.com", "squarespace.com", "surge.sh",
        "trycloudflare.com", "ucoz.ru", "vercel.app", "web.app", "webflow.io",
        "weeblysite.com", "wixsite.com", "wordpress.com", "workers.dev",
        "yolasite.com",
    }
)


def hostname_of(url: str) -> str:
    """Best-effort lowercase host for a URL (empty string when absent)."""

    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.strip(".").lower()


def public_suffix_of(host: str) -> str:
    """Longest known public suffix for ``host`` (falls back to the last label)."""

    host = (host or "").strip(".").lower()
    if not host or coerce_ip_literal(host) is not None:
        return ""
    labels = host.split(".")
    for size in range(min(len(labels) - 1, 4), 0, -1):
        candidate = ".".join(labels[-size:])
        if candidate in MULTI_LABEL_SUFFIXES:
            return candidate
    return labels[-1]


def registrable_domain(host_or_url: str) -> str:
    """Return ``example.co.uk`` for ``a.b.example.co.uk``.

    IP literals are returned unchanged so callers can compare origins without
    special-casing them.
    """

    host = host_or_url
    if "://" in host_or_url or host_or_url.startswith("//"):
        host = hostname_of(host_or_url if "://" in host_or_url else "https:" + host_or_url)
    host = (host or "").strip(".").lower()
    if not host:
        return ""
    if coerce_ip_literal(host) is not None:
        return host

    suffix = public_suffix_of(host)
    if not suffix:
        return host
    if host == suffix:
        return host

    suffix_labels = suffix.count(".") + 1
    labels = host.split(".")
    if len(labels) <= suffix_labels:
        return host
    return ".".join(labels[-(suffix_labels + 1) :])


def subdomain_of(host: str) -> str:
    """The portion of ``host`` in front of its registrable domain."""

    host = (host or "").strip(".").lower()
    base = registrable_domain(host)
    if not base or host == base or not host.endswith(base):
        return ""
    return host[: -(len(base) + 1)]


def same_site(first: str, second: str) -> bool:
    """True when both hosts/URLs share a registrable domain."""

    left = registrable_domain(first)
    right = registrable_domain(second)
    return bool(left) and left == right


def is_shared_hosting(host: str) -> bool:
    """True when the host is published under a known free/shared hosting suffix.

    Compares the *public suffix*, not the registrable domain: the eTLD+1 of
    ``kit.pages.dev`` is ``kit.pages.dev``, so only the suffix reveals that the
    page sits on someone else's platform.
    """

    host = (host or "").strip(".").lower()
    if not host:
        return False
    return public_suffix_of(host) in SHARED_HOSTING_SUFFIXES


# ===========================================================================
# 3. SQLALCHEMY ORM MODEL
# ===========================================================================


class ScanHistory(Base):
    """One completed analysis run, persisted for the analyst timeline."""

    __tablename__ = "scan_history"
    __table_args__ = (
        Index("ix_scan_history_domain_created", "domain", "created_at"),
        Index("ix_scan_history_score_created", "threat_score", "created_at"),
        {"comment": "Immutable audit log of every URL analysed by ThreatLens."},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)

    # --- Target ------------------------------------------------------------
    url: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    final_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    registrable_domain: Mapped[Optional[str]] = mapped_column(String(253), nullable=True)
    resolved_ips: Mapped[Optional[Any]] = mapped_column(JSONColumn, nullable=True)

    # --- Verdict -----------------------------------------------------------
    threat_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    verdict: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommended_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # --- Evidence ----------------------------------------------------------
    risk_factors: Mapped[Optional[Any]] = mapped_column(JSONColumn, nullable=True)
    ai_analysis: Mapped[Optional[Any]] = mapped_column(JSONColumn, nullable=True)
    virustotal: Mapped[Optional[Any]] = mapped_column(JSONColumn, nullable=True)
    response_headers: Mapped[Optional[Any]] = mapped_column(JSONColumn, nullable=True)
    page_metadata: Mapped[Optional[Any]] = mapped_column(JSONColumn, nullable=True)
    raw_report: Mapped[Optional[Any]] = mapped_column(JSONColumn, nullable=True)

    # Base64 payloads are stored apart from `raw_report` so history queries stay
    # cheap and never drag megabytes of image data through the ORM.
    screenshot_base64: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    screenshot_mime: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    dom_excerpt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # --- Telemetry ---------------------------------------------------------
    page_title: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    link_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    form_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    engines_used: Mapped[Optional[Any]] = mapped_column(JSONColumn, nullable=True)
    client_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return (
            f"<ScanHistory id={self.id} scan_id={self.scan_id!r} "
            f"domain={self.domain!r} score={self.threat_score}>"
        )

    def as_history_item(self) -> "ScanHistoryItem":
        return ScanHistoryItem(
            scan_id=self.scan_id,
            url=self.url,
            domain=self.domain,
            threat_score=self.threat_score,
            risk_level=_coerce_risk_level(self.risk_level),
            verdict=self.verdict,
            page_title=self.page_title,
            http_status=self.http_status,
            indicator_count=len(self.risk_factors or []),
            duration_ms=self.duration_ms,
            created_at=self.created_at,
        )


# ===========================================================================
# 4. PYDANTIC SCHEMAS
# ===========================================================================


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FactorSource(str, Enum):
    AI = "ai"
    HEURISTIC = "heuristic"
    THREAT_INTEL = "threat_intel"
    REPUTATION = "reputation"
    NETWORK = "network"


SEVERITY_ORDER: Dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


def _coerce_risk_level(value: Any) -> RiskLevel:
    try:
        return RiskLevel(str(value).lower())
    except ValueError:
        return RiskLevel.UNKNOWN


def score_to_risk_level(score: int) -> RiskLevel:
    """Map a 0-100 threat score onto the analyst-facing band."""

    if score >= 85:
        return RiskLevel.CRITICAL
    if score >= 65:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    if score >= 20:
        return RiskLevel.LOW
    return RiskLevel.SAFE


def risk_level_to_verdict(level: RiskLevel) -> str:
    return {
        RiskLevel.CRITICAL: "Confirmed malicious - block immediately",
        RiskLevel.HIGH: "Likely phishing - do not interact",
        RiskLevel.MEDIUM: "Suspicious - manual review required",
        RiskLevel.LOW: "Low risk - minor anomalies observed",
        RiskLevel.SAFE: "No phishing indicators detected",
        RiskLevel.UNKNOWN: "Inconclusive",
    }[level]


class URLRequest(BaseModel):
    """Inbound scan request. Validation here is the first SSRF gate."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"url": "https://example.com", "include_screenshot": True, "deep_analysis": True}
            ]
        },
    )

    url: str = Field(
        ...,
        min_length=3,
        max_length=MAX_URL_LENGTH,
        description="Absolute http(s) URL to analyse. Internal, loopback, "
        "link-local and cloud-metadata targets are rejected.",
    )
    include_screenshot: bool = Field(
        default=True,
        description="Capture a full-page screenshot and return it as base64.",
    )
    deep_analysis: bool = Field(
        default=True,
        description="Run the LLM analyst pass in addition to the heuristic engine.",
    )
    check_threat_intel: bool = Field(
        default=True,
        description="Query VirusTotal for domain and URL reputation.",
    )

    @field_validator("url", mode="before")
    @classmethod
    def _require_text(cls, value: Any) -> str:
        if value is None:
            raise UnsafeTargetError("URL must not be null.")
        if not isinstance(value, str):
            raise UnsafeTargetError("URL must be a string.")
        return value

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        return validate_and_normalise_url(value)


class RiskFactor(BaseModel):
    """A single scored finding shown in the dashboard's indicator list."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Stable slug, e.g. 'typosquatting'.")
    title: str
    description: str
    category: str = Field(default="general")
    severity: Severity = Field(default=Severity.MEDIUM)
    source: FactorSource = Field(default=FactorSource.HEURISTIC)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    weight: float = Field(default=0.0, ge=0.0, le=100.0)
    evidence: Optional[str] = Field(default=None, max_length=1200)

    @field_validator("title", "description")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        cleaned = (value or "").strip()
        if not cleaned:
            raise ValueError("Risk factor text must not be empty.")
        return cleaned[:1000]


class FormSummary(BaseModel):
    """Extracted ``<form>`` metadata - the core credential-harvesting signal."""

    model_config = ConfigDict(extra="ignore")

    action: str = ""
    resolved_action: str = ""
    method: str = "get"
    input_count: int = 0
    input_names: List[str] = Field(default_factory=list)
    input_types: List[str] = Field(default_factory=list)
    has_password_field: bool = False
    has_email_field: bool = False
    has_hidden_fields: bool = False
    hidden_field_count: int = 0
    is_cross_origin: bool = False
    action_scheme: str = ""
    action_is_insecure: bool = False
    action_is_empty: bool = False


class LinkSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    href: str
    text: str = ""
    is_external: bool = False
    host: str = ""


class PageMetadata(BaseModel):
    """Everything the scraper learned about the rendered document."""

    model_config = ConfigDict(extra="ignore")

    title: str = ""
    description: str = ""
    language: str = ""
    generator: str = ""
    favicon: str = ""
    meta_refresh: str = ""
    canonical_url: str = ""
    text_length: int = 0
    dom_length: int = 0
    link_count: int = 0
    external_link_count: int = 0
    unique_link_hosts: List[str] = Field(default_factory=list)
    form_count: int = 0
    password_field_count: int = 0
    hidden_input_count: int = 0
    iframe_count: int = 0
    iframe_sources: List[str] = Field(default_factory=list)
    script_count: int = 0
    external_script_hosts: List[str] = Field(default_factory=list)
    image_count: int = 0
    redirect_chain: List[str] = Field(default_factory=list)
    obfuscation_markers: List[str] = Field(default_factory=list)
    brand_keywords: List[str] = Field(default_factory=list)


class VirusTotalStats(BaseModel):
    model_config = ConfigDict(extra="ignore")

    harmless: int = 0
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    timeout: int = 0

    @property
    def total(self) -> int:
        return self.harmless + self.malicious + self.suspicious + self.undetected + self.timeout


class VirusTotalReport(BaseModel):
    """Normalised slice of the VirusTotal v3 domain and URL objects."""

    model_config = ConfigDict(extra="ignore")

    available: bool = False
    queried_domain: str = ""
    status: str = "not_configured"
    detail: Optional[str] = None
    domain_stats: VirusTotalStats = Field(default_factory=VirusTotalStats)
    url_stats: Optional[VirusTotalStats] = None
    malicious_engines: List[str] = Field(default_factory=list)
    reputation: Optional[int] = None
    categories: Dict[str, str] = Field(default_factory=dict)
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    last_analysis_date: Optional[str] = None
    permalink: Optional[str] = None

    @property
    def malicious_count(self) -> int:
        url_malicious = self.url_stats.malicious if self.url_stats else 0
        return max(self.domain_stats.malicious, url_malicious)

    @property
    def suspicious_count(self) -> int:
        url_suspicious = self.url_stats.suspicious if self.url_stats else 0
        return max(self.domain_stats.suspicious, url_suspicious)


class AIAnalysis(BaseModel):
    """Structured output of the LangChain phishing-analyst chain."""

    model_config = ConfigDict(extra="ignore")

    available: bool = False
    status: str = "not_configured"
    detail: Optional[str] = None
    provider: str = ""
    ai_model: str = ""
    threat_score: int = Field(default=0, ge=0, le=100)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    verdict: str = ""
    summary: str = ""
    brand_impersonated: Optional[str] = None
    credential_harvesting: bool = False
    social_engineering_tactics: List[str] = Field(default_factory=list)
    recommended_action: str = ""
    indicators: List[RiskFactor] = Field(default_factory=list)
    latency_ms: int = 0
    tokens_used: Optional[int] = None


class ReputationReport(BaseModel):
    """Verdict from the local curated reputation engine (blocklist/allowlist)."""

    model_config = ConfigDict(extra="ignore")

    available: bool = False
    status: str = "skipped"
    detail: Optional[str] = None
    #: "malicious" (blocklist hit), "trusted" (allowlist hit), "unknown", or "".
    classification: str = ""
    matched_value: str = ""
    match_type: str = ""          # exact_domain | exact_host | pattern | allowlist
    category: str = ""            # phishing | malware | scam | abused_infra | trusted
    source: str = ""              # feed / list identifier
    checked_domain: str = ""


class EngineStatus(BaseModel):
    """Per-engine execution outcome, surfaced as badges in the dashboard."""

    model_config = ConfigDict(extra="ignore")

    reputation: str = "skipped"
    scraper: str = "ok"
    heuristics: str = "ok"
    ai: str = "skipped"
    threat_intel: str = "skipped"


class ScoreBreakdown(BaseModel):
    model_config = ConfigDict(extra="ignore")

    reputation_score: int = Field(default=0, ge=0, le=100)
    heuristic_score: int = Field(default=0, ge=0, le=100)
    ai_score: int = Field(default=0, ge=0, le=100)
    threat_intel_score: int = Field(default=0, ge=0, le=100)
    weights: Dict[str, float] = Field(default_factory=dict)
    escalations: List[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    """The full analysis result returned by ``POST /api/scan``."""

    model_config = ConfigDict(extra="ignore")

    scan_id: str
    url: str
    final_url: str = ""
    domain: str = ""
    registrable_domain: str = ""
    resolved_ips: List[str] = Field(default_factory=list)

    threat_score: int = Field(default=0, ge=0, le=100)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    verdict: str = ""
    summary: str = ""
    recommended_action: str = ""

    risk_factors: List[RiskFactor] = Field(default_factory=list)
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    ai_analysis: AIAnalysis = Field(default_factory=AIAnalysis)
    virustotal: VirusTotalReport = Field(default_factory=VirusTotalReport)
    reputation: ReputationReport = Field(default_factory=ReputationReport)

    screenshot_base64: Optional[str] = None
    screenshot_mime: str = "image/jpeg"
    screenshot_bytes: int = 0

    headers: Dict[str, str] = Field(default_factory=dict)
    security_headers: Dict[str, bool] = Field(default_factory=dict)
    http_status: Optional[int] = None
    tls_enabled: bool = False

    page_metadata: PageMetadata = Field(default_factory=PageMetadata)
    forms: List[FormSummary] = Field(default_factory=list)
    links: List[LinkSummary] = Field(default_factory=list)
    dom_excerpt: str = ""

    engines: EngineStatus = Field(default_factory=EngineStatus)
    duration_ms: int = 0
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def top_factors(self, limit: int = 12) -> List[RiskFactor]:
        """Highest-signal findings first: severity, then weight, then confidence."""

        ordered = sorted(
            self.risk_factors,
            key=lambda factor: (
                SEVERITY_ORDER.get(factor.severity.value, 9),
                -factor.weight,
                -factor.confidence,
            ),
        )
        return ordered[:limit]


class ScanHistoryItem(BaseModel):
    """Compact history row (no screenshot, no DOM)."""

    model_config = ConfigDict(extra="ignore")

    scan_id: str
    url: str
    domain: str
    threat_score: int
    risk_level: RiskLevel
    verdict: str
    page_title: Optional[str] = None
    http_status: Optional[int] = None
    indicator_count: int = 0
    duration_ms: int = 0
    created_at: datetime


class ScanHistoryPage(BaseModel):
    items: List[ScanHistoryItem] = Field(default_factory=list)
    total: int = 0
    limit: int = 20
    offset: int = 0


class EngineCapabilities(BaseModel):
    """Advertised to the frontend so it can render honest engine badges."""

    ai_enabled: bool = False
    ai_provider: str = ""
    ai_provider_label: str = ""
    ai_model: str = ""
    ai_setup_url: str = ""
    ai_key_env: str = ""
    threat_intel_enabled: bool = False
    reputation_enabled: bool = False
    reputation_blocklist_size: int = 0
    reputation_allowlist_size: int = 0
    auth_required: bool = False
    max_concurrent_scans: int = 1
    nav_timeout_ms: int = 10000
    rate_limit: str = ""
    version: str = ""


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = ""
    uptime_seconds: float = 0.0
    database: Dict[str, Any] = Field(default_factory=dict)
    engines: Dict[str, bool] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""
    code: str = "error"
    request_id: Optional[str] = None


def dedupe_risk_factors(factors: Sequence[RiskFactor]) -> List[RiskFactor]:
    """Collapse duplicate findings, keeping the highest-weight instance.

    The AI pass and the heuristic engine legitimately spot the same problem;
    analysts should see it once, at its strongest scoring.
    """

    best: Dict[str, RiskFactor] = {}
    for factor in factors:
        key = f"{factor.id}:{factor.title.lower()}"
        current = best.get(key)
        if current is None:
            best[key] = factor
            continue
        current_rank = (SEVERITY_ORDER.get(current.severity.value, 9), -current.weight)
        new_rank = (SEVERITY_ORDER.get(factor.severity.value, 9), -factor.weight)
        if new_rank < current_rank:
            best[key] = factor
    return sorted(
        best.values(),
        key=lambda factor: (
            SEVERITY_ORDER.get(factor.severity.value, 9),
            -factor.weight,
            -factor.confidence,
        ),
    )
