FROM python:3.12-slim
RUN pip install --no-cache-dir dnslib
COPY server.py /app/server.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/server.py"]
