FROM python:3.12-slim

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

CMD ["bash", "run.sh"]
