# ============================================================
# Stage 1: Build Pantegnos
# ============================================================

FROM golang:1.26.3-bookworm AS pantegnos-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG PANTEGNOS_REPO=https://github.com/FrontierTM/Pantegnos.git
ARG PANTEGNOS_REF=main

RUN git clone --depth 1 --branch "${PANTEGNOS_REF}" \
    "${PANTEGNOS_REPO}" Pantegnos

WORKDIR /build/Pantegnos

RUN go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /build/pantegnos \
    ./cmd/pantegnos


# ============================================================
# Stage 2: Python Telegram Bot
# ============================================================

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy Pantegnos binary built in stage 1
RUN mkdir -p /opt/pantegnos

COPY --from=pantegnos-builder \
    /build/pantegnos \
    /opt/pantegnos/pantegnos

RUN chmod +x /opt/pantegnos/pantegnos

# Python dependencies
COPY requirements.txt .

RUN pip install \
    --no-cache-dir \
    -r requirements.txt

# Bot source
COPY mainbot.py .

# Runtime configuration
ENV PANTEGNOS_BIN=/opt/pantegnos/pantegnos
ENV MAX_FILE_SIZE=52428800
ENV PROCESS_TIMEOUT=60

CMD ["python", "mainbot.py"]