FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/sandavdesigns/mailsorter" \
      org.opencontainers.image.description="Browserbasierte Exchange-Mailverteilung"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_DATA_DIR=/data
ARG APP_VERSION=v0.3.3
ENV APP_VERSION=${APP_VERSION}

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY VERSION .
COPY app ./app
RUN mkdir -p /data && useradd --system --uid 10001 mailsorter && chown -R mailsorter:mailsorter /data
USER mailsorter
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
