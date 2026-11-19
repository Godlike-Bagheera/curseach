FROM python:3.12-slim

# Системные библиотеки для WeasyPrint (pango) + шрифты — иначе PDF в контейнере не работает.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV SCANNER_HOST=0.0.0.0 \
    SCANNER_PORT=8001 \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    SCANNER_DB_PATH=/data/scans.db \
    ALLOWED_HOSTS="127.0.0.1,localhost,::1,*.github.dev,*.githubcodespaces.app,*.preview.app.github.dev" \
    SCANNER_ALLOW_PRIVATE_TARGETS=1

EXPOSE 8000 8001
VOLUME ["/data"]

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /app
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('SCANNER_PORT','8001')+'/healthz', timeout=4)" || exit 1

CMD ["bash", "run.sh"]
