FROM python:3.12-slim

WORKDIR /app

COPY src/ src/
COPY pyproject.toml .
COPY README.md .
COPY config/ config/

RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["orchesis", "proxy", "--config", "/app/config/orchesis.yaml"]

# Multi-stage build for minimal image
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim AS runtime

LABEL maintainer="Orchesis Project"
LABEL description="Agent Runtime Governance Layer"

# Security: non-root user
RUN groupadd -r orchesis && useradd -r -g orchesis orchesis

WORKDIR /app

# Install from wheel
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Create runtime directories
RUN mkdir -p /app/.orchesis/keys /app/data && \
    chown -R orchesis:orchesis /app

# Copy defaults
COPY examples/production_policy.yaml /app/policy.yaml
COPY examples/ /app/examples/

USER orchesis

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; r=httpx.get('http://localhost:8080/api/v1/status'); assert r.status_code==200"

EXPOSE 8080 9000

# Default: run control API
CMD ["orchesis", "serve", "--port", "8080", "--policy", "/app/policy.yaml"]
