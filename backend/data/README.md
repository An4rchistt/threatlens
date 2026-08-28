# ThreatLens local reputation data

Two curated files power the **reputation engine** (`backend/reputation.py`), which
runs *before* the sandbox scraper to give instant, high-confidence verdicts on
domains we already know about.

## `allowlist.json`
Registrable domains (eTLD+1) of widely-trusted organisations. A match damps the
final score so the live engines cannot false-positive a major brand. It is
**not** an absolute pass: a genuinely compromised allowlisted host can still be
flagged by the scraper or AI analyst, the reputation layer just lowers the ceiling.

## `threat_feed.json`
Known-bad indicators in three forms:

- **`domains`** — exact registrable-domain matches. Instant malicious verdict.
- **`hosts`** — exact full-host matches (for kits living on a shared parent).
- **`patterns`** — regexes over the host that capture common phishing/scam
  *morphology* (e.g. `brand-secure-login`, `wallet-connect-verify`,
  `usps-customs-fee`). These generalise to domains never seen before, which is
  where most of the real detection value is.

### Honesty note
The seed `domains`/`hosts` entries are **illustrative examples of real phishing
morphology, not a live-scraped list of currently-active malicious sites.** Exact-
domain blocklisting only helps for domains you already know; the patterns are
what generalise. Treat the measured accuracy from `backend/eval/` as the real
signal, not the size of this list.

## Refreshing from live feeds (production)
Point `REPUTATION_FEED_PATH` / `REPUTATION_ALLOWLIST_PATH` at files you refresh
on a schedule from sources such as:

- OpenPhish / PhishTank community feeds (phishing URLs)
- URLhaus by abuse.ch (malware URLs/hosts)
- The Google/Cloudflare/Cisco Umbrella top-domain lists (allowlist seed)

Keep the same JSON schema (`schema_version: 1`). The engine reloads on process
start; there is no hot-reload, so restart the backend after refreshing.
