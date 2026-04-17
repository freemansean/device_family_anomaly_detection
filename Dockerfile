FROM python:3.10-slim

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /unsupervised_anomaly

# Python deps (cached unless requirements.txt changes)
COPY requirements.txt ./
RUN pip install --no-cache-dir --quiet -r requirements.txt

# Application code
COPY sasquatch/ sasquatch/
COPY redis.conf ./

# OUI database — download at build time so first boot is fast.
# Falls back gracefully if the download fails (app still works, OUI = Unknown).
RUN mkdir -p sasquatch/client_anomaly/data \
    && (cd sasquatch && python -m client_anomaly.oui_lookup || true)

# Logs directory
RUN mkdir -p logs

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "main:app", \
     "--app-dir", "sasquatch", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--log-config", "sasquatch/log_config.docker.yaml"]
