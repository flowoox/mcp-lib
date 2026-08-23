FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system --gid 10001 mcp \
    && useradd --system --uid 10001 --gid mcp --home-dir /nonexistent --shell /usr/sbin/nologin mcp

WORKDIR /app

COPY packages/mcp-common /tmp/mcp-common
RUN python -m pip install --no-cache-dir /tmp/mcp-common \
    && rm -rf /tmp/mcp-common

COPY services/entra-mcp /tmp/entra-mcp
RUN python -m pip install --no-cache-dir /tmp/entra-mcp \
    && rm -rf /tmp/entra-mcp

USER 10001:10001
EXPOSE 8088

ENTRYPOINT ["mcp-entra"]
