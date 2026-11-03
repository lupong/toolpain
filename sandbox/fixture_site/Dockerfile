FROM python:3.12-slim
WORKDIR /site
COPY *.html /site/
CMD ["python", "-m", "http.server", "80", "--directory", "/site"]
