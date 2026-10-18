FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -r voiceapp && useradd -r -g voiceapp -d /app -s /sbin/nologin voiceapp

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . && \
    mkdir -p /data && chown -R voiceapp:voiceapp /app /data

USER voiceapp
ENV AI_VOICE_DATA_DIR=/data \
    AI_VOICE_TRANSPORT=http \
    AI_VOICE_BIND_HOST=0.0.0.0 \
    AI_VOICE_BIND_PORT=8400

EXPOSE 8400/tcp
EXPOSE 30000-30040/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8400/healthz', timeout=3)"

CMD ["ai-assistant-voice", "--transport", "http"]
