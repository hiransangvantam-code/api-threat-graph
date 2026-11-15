#!/bin/sh
# Review an open-source system running on its REAL images (macOS / Linux):
#   sh real.sh robot-shop
# The systems: robot-shop petclinic lakeside-mutual hotel-reservation piggymetrics bookinfo online-boutique
# (opensource/real/README.md says what each one needs). Needs Docker and internet access; the first run
# of a system downloads its images, a few GB for the Java ones.
#
# 1. download the system's code at the pinned commit (opensource/<id>/upstream), if not there yet
# 2. start the system from its real images, on the network ATG joins
# 3. start ATG with ATG_PORT 18080, so it does not clash with a system's own port 8080
# 4. send users through the ATG sidecar: the system's own load generator if it has one, then
#    opensource/real/<id>/load.txt (anonymous requests)
# 5. scan, 6. keep the result in results/opensource/atg-real/<id>.json, 7. stop both Dockers
# Send back results/opensource/atg-real/: python bench/run_opensource.py --score-only --tag real scores it.
cd "$(dirname "$0")" || exit 1
SID="$1"
K="opensource/real/$SID"
step() { printf "\n== %s\n" "$1"; }
fail() { echo; echo "Stopped: $1"; exit 1; }
if [ -z "$SID" ] || [ ! -f "$K/kit.env" ]; then
  echo "Usage: sh real.sh <system>. The systems with a real-image kit are:"
  for d in opensource/real/*/kit.env; do echo "  $(basename "$(dirname "$d")")"; done
  exit 1
fi
command -v docker >/dev/null 2>&1 || fail "Docker is not installed."
docker info >/dev/null 2>&1 || fail "Docker is not running."

set -a
. "./$K/kit.env"
. "./opensource/$SID/atg.env"
set +a
export ATG_PORT="${ATG_PORT:-18080}" ATG_SYSTEM="$SID"
for s in $SECRETS; do   # passwords the system needs: random, in this run's environment only
  export "$s=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
done
C="docker compose -p real-$SID"
for f in $COMPOSE_FILES; do C="$C -f $f"; done
A="docker compose -f docker-compose.yml"
[ -f "$K/atg.override.yml" ] && A="$A -f $K/atg.override.yml"
URL="http://localhost:$ATG_PORT/"

step "1/7 Download $TARGET_NAME at the pinned commit"
if [ -d "opensource/$SID/upstream" ]; then echo "already there: opensource/$SID/upstream"
else
  docker run --rm -v "$PWD:/app" -w /app python:3.12-alpine sh -c \
    "apk add --no-cache git >/dev/null && pip install -q pyyaml && python opensource/fetch.py $SID" || fail "the download"
fi

step "2/7 Start $TARGET_NAME from its real images (first time: downloads, sometimes a build)"
$A down -v --remove-orphans >/dev/null 2>&1
$C up -d || fail "the system did not start ($C logs)"
echo "Giving it ${WARMUP:-90} s to start up ..."
sleep "${WARMUP:-90}"

step "3/7 Start ATG on the network $TARGET_NETWORK"
$A up -d --build || fail "the ATG platform did not start"
i=0
until curl -s -o /dev/null "$URL"; do
  i=$((i + 1)); [ "$i" -gt 90 ] && fail "the ATG page did not come up ($A logs atg)"
  sleep 2
done
echo "ATG is at $URL"

step "4/7 Users: their requests go through the ATG sidecar"
if [ -n "$OWN_LOAD" ]; then
  echo "$TARGET_NAME's own load generator ($OWN_LOAD), about two minutes:"
  $C --profile users run --rm "$OWN_LOAD" >/dev/null 2>&1 || echo "  (the load generator stopped with an error; continuing)"
fi
echo "Anonymous requests from $K/load.txt:"
docker run --rm --network "$TARGET_NETWORK" -v "$PWD/opensource/real:/kit:ro" --entrypoint sh \
  "${CURL_IMAGE:-curlimages/curl:8.11.0}" /kit/load.sh "/kit/$SID/load.txt" || fail "the requests"

step "5/7 Scan: Phases 1-4"
$A exec -T atg python docker/scan.py --label "real-$SID" --manifests k8s || fail "the scan"

step "6/7 Keep the result"
mkdir -p results/opensource/atg-real
$A exec -T -e ATG_SYSTEM="$SID" atg python - < opensource/real/dump.py > "results/opensource/atg-real/$SID.json" || fail "copying the result"
echo "results/opensource/atg-real/$SID.json  (the pages are at $URL and in output/site until the next review)"

step "7/7 Stop both Dockers"
$C --profile users down -v --remove-orphans >/dev/null 2>&1
$A stop >/dev/null 2>&1
echo
echo "Done. Run the next system, or zip results/opensource/atg-real and send it back."
echo "sh stop.sh removes the ATG Docker and its data when you are finished."
