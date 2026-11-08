FROM python:3.12-slim
COPY server.py /srv/fixture_server.py
COPY *.html /site/
WORKDIR /site
CMD ["python", "/srv/fixture_server.py"]
