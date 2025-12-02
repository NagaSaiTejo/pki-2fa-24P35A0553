FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    cron \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

RUN mkdir -p /data /cron

COPY cron/2fa-cron /etc/cron.d/2fa-cron

RUN chmod 0644 /etc/cron.d/2fa-cron

RUN crontab /etc/cron.d/2fa-cron

RUN touch /cron/cron.log && chmod 666 /cron/cron.log

ENV USE_CONTAINER_PATH=1

CMD service cron start && uvicorn app.main:app --host 0.0.0.0 --port 8080
