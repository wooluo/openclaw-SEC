# Multi-stage Dockerfile for OpenClaw Security Shield
# Stage 1: Builder
FROM python:3.11-slim AS builder

# Set build arguments
ARG VERSION=1.1.0

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy project files
WORKDIR /build
COPY pyproject.toml setup.py ./
COPY openclaw_shield/ ./openclaw_shield/
COPY config/ ./config/

# Install package and dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install -e ".[network,ai]"

# Stage 2: Runtime
FROM python:3.11-slim

# Set runtime labels
LABEL maintainer="OpenClaw Security Team <security@openclaw.ai>" \
      version="${VERSION}" \
      description="OpenClaw Security Shield - Comprehensive security protection system"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    OPENCLAW_CONFIG_DIR=/config \
    OPENCLAW_DATA_DIR=/data \
    OPENCLAW_LOG_DIR=/logs

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi7 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash openclaw && \
    mkdir -p /config /data /logs /quarantine && \
    chown -R openclaw:openclaw /config /data /logs /quarantine

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy configuration files
COPY config/ /config/
COPY openclaw_shield/ /opt/openclaw_shield/

# Set working directory
WORKDIR /app

# Switch to non-root user
USER openclaw

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from openclaw_shield import SecurityShield; s = SecurityShield(); print('OK')" || exit 1

# Default command
ENTRYPOINT ["openclaw-shield"]
CMD ["--help"]

# Expose ports (for future web interface)
EXPOSE 8000
