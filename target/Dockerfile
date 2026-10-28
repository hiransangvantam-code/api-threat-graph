# ShopLite, the company's system under review. Built from demo_target/ only:
# the target image contains none of the ATG platform's code.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY demo_target/requirements.txt demo_target/requirements.txt
RUN pip install -r demo_target/requirements.txt
COPY demo_target/ demo_target/
