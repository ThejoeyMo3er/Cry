# syntax=docker/dockerfile:1

FROM golang:1.26.3-bookworm AS engine-builder
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/FrontierTM/Pantegnos.git .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /opt/pantegnos/pantegnos ./cmd/pantegnos

FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/app/data \
    PANTEGNOS_BIN=/opt/pantegnos/pantegnos

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mainbot_v1.py /app/mainbot.py
COPY --from=engine-builder /opt/pantegnos/pantegnos /opt/pantegnos/pantegnos
RUN chmod +x /opt/pantegnos/pantegnos && mkdir -p /app/data

CMD ["python", "/app/mainbot.py"]
