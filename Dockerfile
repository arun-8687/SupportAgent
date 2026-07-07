# syntax=docker/dockerfile:1
#
# One image, two entrypoints. The worker Deployment runs the always-on
# Service Bus listener; the API Deployment runs uvicorn and serves the built
# SPA. Both share this image so there's a single artifact to build and scan.
#
#   docker build -t <registry>/sre-agent:<tag> .
#   # worker: python -m sre_agent.main listen
#   # api:    uvicorn sre_agent.webapi.main:app --host 0.0.0.0 --port 8080

# ---- Stage 1: build the React SPA ----
FROM node:20-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: python runtime ----
FROM python:3.11-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    SRE_AGENT_WEBAPI_SPA_DIST_DIR=/app/frontend/dist \
    SRE_AGENT_DATA_DIR=/data
WORKDIR /app

RUN groupadd -r sre && useradd -r -g sre -d /app sre

# Install deps first (cached layer) using only the requirements files.
COPY sre_agent/requirements.txt sre_agent/requirements-prod.txt /app/sre_agent/
RUN pip install --no-cache-dir -r /app/sre_agent/requirements-prod.txt

# App code + the built SPA.
COPY sre_agent/ /app/sre_agent/
COPY --from=frontend /app/frontend/dist /app/frontend/dist

# /data is the durable state mount (Azure Files PVC in k8s); knowledge/memory
# files live here so they survive pod restarts and are shared across replicas.
RUN mkdir -p /data && chown -R sre:sre /app /data
USER sre
EXPOSE 8080

# Default to the API; the worker Deployment overrides `command`.
CMD ["uvicorn", "sre_agent.webapi.main:app", "--host", "0.0.0.0", "--port", "8080"]
