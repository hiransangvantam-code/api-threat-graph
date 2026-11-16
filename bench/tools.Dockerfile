# The eight free tools of the open-source benchmark in one image, so the comparison runs anywhere
# Docker runs (BENCH-Windows.bat / bench.sh build it the first time, about 5-10 minutes):
#   Checkov 3.4.5, Bandit 1.9.4, njsscan 1.0.1 (pip) · Spectral 6.17.1 + OWASP ruleset 2.0.1 (npm)
#   Kubescape v3.0.18, kube-linter 0.7.1, Polaris 9.6.1, gosec 2.21.4 (GitHub releases) · Go for gosec
# plus PyYAML, matplotlib and markdown for scoring, figures and the comparison page.
ARG PY_IMAGE=python:3.12-slim
ARG NODE_IMAGE=node:20-slim
ARG GO_IMAGE=golang:1.22-alpine

FROM ${NODE_IMAGE} AS node
RUN mkdir -p /out && cp -a "$(dirname "$(dirname "$(readlink -f "$(command -v node)")")")" /out/node

FROM ${GO_IMAGE} AS go
RUN mkdir -p /out && cp -a "$(go env GOROOT)" /out/go

FROM ${PY_IMAGE}
COPY --from=node /out/node /opt/node
COPY --from=go /out/go /opt/go
ENV PATH=/opt/node/bin:/opt/go/bin:$PATH TOOLS_DIR=/opt/tools ATG_GO_BIN=/opt/go/bin \
    PIP_DISABLE_PIP_VERSION_CHECK=1 MPLCONFIGDIR=/tmp/mpl
WORKDIR /opt/tools
RUN pip install --no-cache-dir pyyaml==6.0.2 matplotlib==3.9.2 markdown==3.7 \
 && python -m venv venv \
 && venv/bin/pip install --no-cache-dir checkov==3.4.5 bandit==1.9.4 njsscan==1.0.1
RUN if [ -n "$SSL_CERT_FILE" ]; then npm config set cafile "$SSL_CERT_FILE"; fi \
 && npm install --no-audit --no-fund --loglevel=error @stoplight/spectral-cli@6.17.1 @stoplight/spectral-owasp-ruleset@2.0.1 \
 && printf 'extends: ["@stoplight/spectral-owasp-ruleset"]\n' > owasp.spectral.yaml
COPY bench/tools_fetch.py /opt/tools/tools_fetch.py
RUN python tools_fetch.py /opt/tools/bin
WORKDIR /work
