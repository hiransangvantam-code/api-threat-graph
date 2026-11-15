#!/bin/sh
# Start both Dockers and run the review (macOS / Linux):
#   sh start.sh            ShopLite, scanned before and after its fixes
#   sh start.sh paynow     one of the ten test companies in companies/ (see companies/README.md)
#   sh start.sh bookinfo   one of the ten open-source systems in opensource/, with stand-in services
#                          (see opensource/README.md; real images: sh real.sh <name>)
#   company Docker: ShopLite (target/docker-compose.yml) or companies/<name>/docker-compose.yml
#   ATG Docker:     our platform (docker-compose.yml), attached to the company's network
cd "$(dirname "$0")" || exit 1
command -v docker >/dev/null 2>&1 || { echo "Docker is not installed. Get Docker Desktop: https://www.docker.com/products/docker-desktop/"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop, wait until it says 'Engine running', then run this again."; exit 1; }

PORT="${ATG_PORT:-8080}"
URL="http://localhost:$PORT/"
T="docker compose -f target/docker-compose.yml"
step() { printf "\n== %s\n" "$1"; }
fail() { echo; echo "Stopped: $1"; exit 1; }
wait_page() {
  printf "Waiting for %s " "$URL"
  i=0
  until curl -s -o /dev/null "$URL"; do
    i=$((i + 1)); [ "$i" -gt 90 ] && fail "the ATG page did not come up (docker compose logs atg)"
    printf "."; sleep 2
  done
  echo
  case "$(uname)" in
    Darwin) open "$URL" ;;
    *) command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL" >/dev/null 2>&1 ;;
  esac
  echo "Opened $URL"
}

if [ -n "$1" ]; then
  CO="$1"
  F=companies
  [ ! -f "companies/$CO/atg.env" ] && [ -f "opensource/$CO/atg.env" ] && F=opensource
  if [ ! -f "$F/$CO/atg.env" ]; then
    echo "There is no system called \"$CO\". The ten test companies are:"
    for d in companies/*/atg.env; do echo "  $(basename "$(dirname "$d")")"; done
    echo "and the ten open-source systems (stand-ins; for their real images: sh real.sh <name>):"
    for d in opensource/*/atg.env; do echo "  $(basename "$(dirname "$d")")"; done
    echo "Example: sh start.sh paynow   or   sh start.sh bookinfo"
    exit 1
  fi
  set -a; . "./$F/$CO/atg.env"; set +a
  if [ "$F" = opensource ] && [ ! -d "opensource/$CO/upstream" ]; then
    step "0/4 Download $TARGET_NAME at the pinned commit (ATG reads its real deployment files)"
    docker run --rm -v "$PWD:/app" -w /app python:3.12-alpine sh -c \
      "apk add --no-cache git >/dev/null && pip install -q pyyaml && python opensource/fetch.py $CO" || fail "the download"
  fi
  C="docker compose -f $F/$CO/docker-compose.yml"
  echo "A fresh review of $TARGET_NAME: the ATG Docker of any earlier review is stopped first and its data deleted."
  docker compose down -v --remove-orphans >/dev/null 2>&1
  step "1/4 Company Docker: start $TARGET_NAME (first time: a few minutes to build)"
  $C up -d --build --wait || fail "the company's system did not start"
  step "2/4 ATG Docker: start our platform on the network $TARGET_NETWORK"
  docker compose up -d --build || fail "the ATG platform did not start"
  wait_page
  step "3/4 $TARGET_NAME's users send requests; they go through the ATG sidecar"
  $C run --rm users || fail "the traffic did not run"
  step "4/4 Scan: Phases 1-4 on $TARGET_NAME"
  docker compose exec -T atg python docker/scan.py --label "$CO" --manifests k8s || fail "the scan"
  echo
  echo "Done. $URL shows $TARGET_NAME's threat graph."
  if [ "$F" = companies ]; then echo "What was planted in $TARGET_NAME on purpose: companies/$CO/README.md"
  else echo "Its labelled weaknesses: opensource/$CO/system.yaml (the services running are stand-ins)"; fi
  echo "sh stop.sh   stops both Dockers and deletes the review data."
  exit 0
fi

echo "Every start is a fresh review: the pages of the previous review in output/site are replaced."
# versions before 1.3 kept captured traffic in these volumes on disk; remove them if they are still there
docker volume rm atg_atg-capture atg_atg-telemetry >/dev/null 2>&1

step "1/6 Company Docker: start ShopLite as shipped (first time: a few minutes to build)"
export SHOPLITE_HARDENED=0 SHOPLITE_MANIFESTS=k8s
$T up -d --build --wait || fail "the company's system did not start"

step "2/6 ATG Docker: start our platform (sidecar proxy, OTel Collector, PostgreSQL, scanner, web)"
docker compose up -d --build || fail "the ATG platform did not start"
wait_page
echo "(the page shows the status of both Dockers until the first scan is done)"

step "3/6 Customers use the shop; their traffic goes through the ATG sidecar"
$T run --rm users || fail "the customer traffic did not run"

step "4/6 Scan 1: Phases 1-4 on ShopLite as shipped"
docker compose exec -T atg python docker/scan.py --label vulnerable --manifests k8s || fail "scan 1"

step "5/6 The company deploys the fixes; customers use the shop again"
export SHOPLITE_HARDENED=1 SHOPLITE_MANIFESTS=k8s-hardened
$T up -d --wait || fail "the fixed version did not start"
$T run --rm users || fail "the customer traffic did not run"

step "6/6 Scan 2: Phases 1-4 on ShopLite with the fixes"
docker compose exec -T atg python docker/scan.py --label hardened --manifests k8s-hardened || fail "scan 2"

echo
echo "Done. $URL shows the threat graph, both scans and the trend."
echo "The threat graph files (GraphML, JSON, SARIF, SVG) are in output/site/exports/."
echo "sh stop.sh   stops both Dockers and deletes the review data (pages and exports stay)."
echo "sh clean.sh  deletes the pages and exports too, once you have handed them over."
