# Sandbox run image for the decoy-trap demo server (build stage has network; run stage does not).
FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "mcp>=2.0"
WORKDIR /app
COPY server.py /app/server.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python", "/app/server.py"]
