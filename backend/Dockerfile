# ---------------------------------------------------------------------------
# ThreatLens backend: FastAPI + Playwright (Chromium) analysis engine.
# The Playwright base image ships the exact OS libraries Chromium needs, so
# the browser and the API live in a single, reproducible container.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/playwright/python:v1.40.0-jammy

LABEL org.opencontainers.image.title="ThreatLens Backend" \
      org.opencontainers.image.description="AI-powered web threat detection and phishing analysis engine" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    APP_HOME=/app

WORKDIR ${APP_HOME}

# 1. Python dependencies first so the layer caches across code edits.
COPY requirements.txt ${APP_HOME}/requirements.txt
RUN python3 -m pip install --upgrade pip setuptools wheel \
 && python3 -m pip install --no-cache-dir -r ${APP_HOME}/requirements.txt

# 2. Browser binaries. The base image already contains them, but re-running the
#    installer guarantees the revision matches the pinned playwright wheel and
#    makes the image valid even if the base tag is bumped.
RUN python3 -m playwright install --with-deps chromium \
 && chmod -R a+rX /ms-playwright

# 3. Application code.
COPY . ${APP_HOME}

# 4. Drop privileges. `pwuser` ships with the Playwright base image.
RUN mkdir -p ${APP_HOME}/artifacts \
 && chown -R pwuser:pwuser ${APP_HOME}

USER pwuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=10s --start-period=40s --retries=5 \
    CMD python3 -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=5).status == 200 else 1)"

CMD uvicorn main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --workers 1 \
    --timeout-keep-alive 75 \
    --proxy-headers \
    --forwarded-allow-ips "*" \
    --no-server-header
