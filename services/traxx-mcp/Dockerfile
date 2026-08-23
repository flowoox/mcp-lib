FROM python:3.12-slim AS runtime

ARG VERSION=0.3.7
LABEL org.opencontainers.image.title="flowoox Traxx MCP" \
      org.opencontainers.image.description="MCP connector for Traxx/BeMusic TUS uploads, metadata normalization and cover embedding" \
      org.opencontainers.image.source="https://github.com/flowoox/mcp-lib" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8082 \
    TRAXX_CONFIG_FILE=/data/config.json \
    DOWNLOADS_DIR=/downloads

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY constraints/python312.lock /build/constraints/python312.lock
COPY packages/mcp-common /build/packages/mcp-common
COPY services/traxx-mcp /build/service
RUN python -m pip install --constraint /build/constraints/python312.lock --upgrade pip \
    && python -m pip install --constraint /build/constraints/python312.lock ./packages/mcp-common ./service \
    && python -m pip check

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home app \
    && mkdir -p /data /downloads \
    && chown -R app:app /data /downloads

USER app
WORKDIR /app
EXPOSE 8082
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import socket; connection = socket.create_connection(('127.0.0.1', 8082), 3); connection.close()"
CMD ["mcp-traxx"]
