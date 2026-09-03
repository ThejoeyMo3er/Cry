# syntax=docker/dockerfile:1

# =========================
# Stage 1: Build engine
# =========================
FROM golang:1.26.3-bookworm AS engine-builder

WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/FrontierTM/Pantegnos.git .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -o /opt/pantegnos/pantegnos \
    ./cmd/pantegnos


# =========================
# Stage 2: Python bot
# =========================
FROM python:3.12-slim-bookworm

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV PANTEGNOS_BIN=/opt/pantegnos/pantegnos
ENV DATA_DIR=/app/data
ENV MAX_CONCURRENT_JOBS=4

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# نسخه فعلی بات
COPY mainbot_v2.py /app/mainbot.py

# انتقال Engine ساخته‌شده
COPY --from=engine-builder \
    /opt/pantegnos/pantegnos \
    /opt/pantegnos/pantegnos

RUN chmod +x /opt/pantegnos/pantegnos \
    && mkdir -p /app/data

CMD ["python", "-u", "/app/mainbot.py"]
