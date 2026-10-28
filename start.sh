#!/bin/sh
# Start both Dockers and run the review (macOS / Linux):   sh start.sh
#   company Docker: ShopLite (target/docker-compose.yml)
#   ATG Docker:     our platform (docker-compose.yml), attached to the company's network
cd "$(dirname "$0")" || exit 1
command -v docker >/dev/null 2>&1 || { echo "Docker is not installed. Get Docker Desktop: https://www.docker.com/products/docker-desktop/"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop, wait until it says 'Engine running', then run this again."; exit 1; }

PORT="${ATG_PORT:-8080}"
URL="http://localhost:$PORT/"
T="docker compose -f target/docker-compose.yml"
step() { printf "\n== %s\n" "$1"; }
fail() { echo; echo "Stopped: $1"; exit 1; }

step "1/6 Company Docker: start ShopLite as shipped (first time: a few minutes to build)"
export SHOPLITE_HARDENED=0 SHOPLITE_MANIFESTS=k8s
$T up -d --build --wait || fail "the company's system did not start"

step "2/6 ATG Docker: start our platform (sidecar proxy, OTel Collector, PostgreSQL, scanner, web)"
docker compose up -d --build || fail "the ATG platform did not start"
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
echo "Opened $URL (it shows the status of both Dockers until the first scan is done)"

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
echo "Stop everything with: sh stop.sh"
