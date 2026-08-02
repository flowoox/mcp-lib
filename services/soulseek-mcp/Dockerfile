FROM python:3.12-slim AS runtime

ARG VERSION=0.2.0
LABEL org.opencontainers.image.title="flowoox Soulseek MCP" \
      org.opencontainers.image.description="MCP service for complete Soulseek/slskd album folders" \
      org.opencontainers.image.source="https://github.com/flowoox/mcp-lib" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8081 \
    SOULSEEK_CONFIG_FILE=/data/config.json \
    SOULSEEK_CANDIDATE_FILE=/data/candidates.json \
    DOWNLOADS_DIR=/downloads \
    SLSKD_CONFIG_PATH=/slskd/slskd.yml

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY packages/mcp-common /build/packages/mcp-common
COPY services/soulseek-mcp /build/service
RUN python -m pip install --upgrade pip \
    && python -m pip install ./packages/mcp-common ./service

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home app \
    && mkdir -p /data /downloads /slskd \
    && chown -R app:app /data /downloads /slskd

USER app
WORKDIR /app
EXPOSE 8081
CMD ["mcp-soulseek"]
