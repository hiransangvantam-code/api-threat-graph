# API Threat Graph prototype: ShopLite demo + Phases 1-4 + the result pages, in one image.
#   docker compose up --build      then open http://localhost:8080
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
