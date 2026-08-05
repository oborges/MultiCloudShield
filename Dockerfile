# syntax=docker/dockerfile:1.7
FROM node:25-slim AS web-build
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.9.24 AS uv

FROM python:3.13-slim AS python-build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
RUN uv sync --frozen --no-dev --extra all-providers

FROM python:3.13-slim AS runtime
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AZURE_TOKEN_CREDENTIALS=prod
WORKDIR /app
COPY --from=python-build --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 src/ src/
COPY --chown=10001:10001 alembic.ini ./
COPY --chown=10001:10001 alembic/ alembic/
COPY --from=web-build --chown=10001:10001 /build/web/dist web/dist/
USER 10001:10001
EXPOSE 8080
CMD ["mcs-api"]
