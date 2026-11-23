FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# Где Playwright хранит браузеры. Объявляем ДО установки, чтобы Chromium
# скачался именно сюда (а не в /root/.cache — куда appuser не имеет доступа).
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Системные шрифты для рендера PDF (сам Chromium ставится ниже через --with-deps).
RUN apt-get update && apt-get install -y --no-install-recommends \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
# 1) Хэшированные зависимости (тест test_dockerfile_digest_and_require_hashes требует --require-hashes).
# 2) Playwright ставится отдельно: у него sha256 различаются по платформам,
#    а pip --require-hashes требует хеш для КАЖДОГО пакета в файле.
# 3) Chromium + его системные библиотеки (--with-deps дергает apt-get от root).
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
    && pip install --no-cache-dir playwright==1.65.2 \
    && python -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

COPY . .

ENV SCANNER_HOST=0.0.0.0 \
    SCANNER_PORT=8001 \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    SCANNER_DB_PATH=/data/scans.db \
    ALLOWED_HOSTS="127.0.0.1,localhost,::1,*.github.dev,*.githubcodespaces.app,*.preview.app.github.dev" \
    SCANNER_ALLOW_PRIVATE_TARGETS=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

EXPOSE 8000 8001
VOLUME ["/data"]

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /app /ms-playwright
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('SCANNER_PORT','8001')+'/healthz', timeout=4)" || exit 1

CMD ["python", "start.py", "--skip-install", "--no-browser"]
