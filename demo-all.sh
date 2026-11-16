#!/bin/sh
# Review all ten open-source systems one after another and keep each one's pages, for a demo
# (macOS / Linux):
#   sh demo-all.sh                      all ten (about 30-40 minutes the first time)
#   sh demo-all.sh bookinfo petclinic   only these (open-source systems or test companies)
# Each system: start it (stand-in services), start ATG on its network, run its users, scan, copy
# output/site to demo/<name>/, stop both. Afterwards open demo/index.html: one card per system.
cd "$(dirname "$0")" || exit 1
command -v docker >/dev/null 2>&1 || { echo "Docker is not installed."; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop first."; exit 1; }
SYSTEMS="${*:-online-boutique bank-of-anthos robot-shop acme-air petclinic piggymetrics lakeside-mutual ftgo hotel-reservation bookinfo}"
PORT="${ATG_PORT:-8080}"
mkdir -p demo
ok=""; bad=""
for CO in $SYSTEMS; do
  F=opensource
  [ -f "opensource/$CO/atg.env" ] || F=companies
  if [ ! -f "$F/$CO/atg.env" ]; then echo "== $CO: no such system, skipped"; bad="$bad $CO"; continue; fi
  set -a; . "./$F/$CO/atg.env"; set +a
  echo; echo "== $CO ($TARGET_NAME)"
  if [ "$F" = opensource ] && [ ! -d "opensource/$CO/upstream" ]; then
    echo "   downloading its code at the pinned commit"
    docker run --rm -v "$PWD:/app" -w /app python:3.12-alpine sh -c \
      "apk add --no-cache git >/dev/null && pip install -q pyyaml && python opensource/fetch.py $CO" >/dev/null 2>&1 \
      || { echo "   download failed, skipped"; bad="$bad $CO"; continue; }
  fi
  C="docker compose -f $F/$CO/docker-compose.yml"
  docker compose down -v --remove-orphans >/dev/null 2>&1
  echo "   starting the system and ATG"
  if ! $C up -d --build --wait >/dev/null 2>&1 || ! docker compose up -d --build >/dev/null 2>&1; then
    echo "   did not start, skipped ($C logs)"; bad="$bad $CO"
    $C --profile users down -v --remove-orphans >/dev/null 2>&1; continue
  fi
  i=0
  until curl -s -o /dev/null "http://localhost:$PORT/"; do i=$((i + 1)); [ "$i" -gt 90 ] && break; sleep 2; done
  U=results/opensource/atg-laptop/usage   # CPU and memory of ATG's four containers (bench/usage.py; read by bench.sh)
  if [ "$F" = opensource ]; then
    mkdir -p "$U"; echo users > "$U/$CO.stage"
    docker rm -f atg-usage >/dev/null 2>&1
    docker run -d --name atg-usage --network none -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/repo" \
      api-threat-graph:1.6 python /repo/bench/usage.py "/repo/$U/$CO.json" >/dev/null 2>&1
  fi
  echo "   users: $($C run --rm users 2>/dev/null | tail -1)"
  [ "$F" = opensource ] && echo scan > "$U/$CO.stage"
  docker compose exec -T atg python docker/scan.py --label "$CO" --manifests k8s > "demo/$CO.log" 2>&1
  rc=$?
  docker rm -f atg-usage >/dev/null 2>&1; rm -f "$U/$CO.stage"
  if [ "$rc" -eq 0 ]; then
    echo "   $(grep '^\[scan\] '"$CO"':' "demo/$CO.log" | tail -1)"
    rm -rf "demo/$CO"; cp -r output/site "demo/$CO"; mv "demo/$CO.log" "demo/$CO/scan.log"
    if [ "$F" = opensource ]; then   # ATG's endpoints and findings, for bench.sh (the comparison with other tools)
      mkdir -p results/opensource/atg-laptop
      docker compose exec -T -e ATG_SYSTEM="$CO" atg python - < opensource/real/dump.py > "results/opensource/atg-laptop/$CO.json"
    fi
    ok="$ok $CO"
  else
    echo "   the scan failed: demo/$CO.log"; bad="$bad $CO"
  fi
  docker compose down -v --remove-orphans >/dev/null 2>&1
  $C --profile users down -v --remove-orphans >/dev/null 2>&1
done
echo
echo "Done. Reviewed:${ok:- none}"
[ -n "$bad" ] && echo "Not reviewed:$bad (run them again alone: sh demo-all.sh <name>)"
echo "Open demo/index.html. Next, the comparison with eight other tools: sh bench.sh"
