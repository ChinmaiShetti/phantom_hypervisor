# PHANTOM license server image.
# Build context is the REPOSITORY ROOT (shared security/ + dashboard/ packages):
#   docker build -f server/Dockerfile -t phantom-server .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_ENV=production \
    DATA_DIR=/data \
    PORT=8000

WORKDIR /app

# Dependencies first so this layer is cached between code changes
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY security/ security/
COPY monitoring/ monitoring/
COPY server/ server/
COPY dashboard/ dashboard/
COPY sample_app/ sample_app/

# Run as an unprivileged user; /data is the only writable location (volume mount point)
RUN useradd --create-home --uid 10001 phantom \
 && mkdir -p /data \
 && chown phantom:phantom /data \
 && chmod -R a-w /app
USER phantom

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8000'), timeout=3)"

# Render injects $PORT; bind to 0.0.0.0 so traffic from outside the container reaches uvicorn.
# --proxy-headers lets rate limiting see the real client IP behind Render's HTTPS proxy.
CMD ["sh", "-c", "exec uvicorn server.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
