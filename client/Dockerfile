# PHANTOM protected client image (simulated DRM-protected application).
# Build context is the REPOSITORY ROOT:
#   docker build -f client/Dockerfile -t phantom-client .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CLIENT_DATA_DIR=/data \
    LICENSE_SERVER_URL=http://phantom-server:8000

WORKDIR /app

COPY client/requirements.txt client/requirements.txt
RUN pip install -r client/requirements.txt

# Note: no server/ code and no private key are ever copied into this image.
COPY security/ security/
COPY monitoring/ monitoring/
COPY client/ client/
COPY sample_app/ sample_app/

RUN useradd --create-home --uid 10002 phantom \
 && mkdir -p /data \
 && chown phantom:phantom /data \
 && chmod -R a-w /app
USER phantom

ENTRYPOINT ["python", "-m", "client.main"]
CMD ["run"]
