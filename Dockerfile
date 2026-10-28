# The ATG platform image (Phases 1-4 and the web pages). The same image runs the
# mitmproxy sidecar (atg-proxy) and the scanner/web view (atg); see docker-compose.yml.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt requirements-postgres.txt ./
RUN pip install -r requirements.txt -r requirements-postgres.txt

COPY . .

EXPOSE 8888
CMD ["python", "docker/serve.py"]
