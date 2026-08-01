FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN python -m pip install --upgrade pip \
    && python -m pip install .

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home app \
    && mkdir -p /data /downloads \
    && chown -R app:app /app /data /downloads

USER app

FROM base AS soulseek
EXPOSE 8081
CMD ["mcp-soulseek"]

FROM base AS traxx
EXPOSE 8082
CMD ["mcp-traxx"]
