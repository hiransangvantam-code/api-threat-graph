# Python services of the test companies (companies/*/company.yaml with language: python),
# and the traffic generator every company uses. Contains none of the ATG platform's code.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY service.py traffic.py ./
USER 10001
CMD ["python", "service.py"]
