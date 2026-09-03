# ============================================================
# Stage 1 - build the current Pantegnos project automatically
# ============================================================

FROM golang:1.26.3-bookworm AS engine-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG PANTEGNOS_REPO=https://github.com/FrontierTM/Pantegnos.git
ARG PANTEGNOS_REF=main

RUN git clone --depth 1 --branch "${PANTEGNOS_REF}" \
    "${PANTEGNOS_REPO}" /build/Pantegnos

WORKDIR /build/Pantegnos

RUN go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /build/pantegnos \
    ./cmd/pantegnos


# ============================================================
# Stage 2 - ProDecryptor
# ============================================================

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN mkdir -p /app/data /opt/pantegnos

COPY --from=engine-builder /build/pantegnos /opt/pantegnos/pantegnos
RUN chmod +x /opt/pantegnos/pantegnos

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

COPY mainbot.py /app/mainbot.py

ENV DATA_DIR=/app/data
ENV PANTEGNOS_BIN=/opt/pantegnos/pantegnos
ENV MAX_CONCURRENT_JOBS=2

CMD ["python", "/app/mainbot.py"]
