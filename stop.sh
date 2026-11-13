#!/bin/sh
# Stop both Dockers and delete the review data (macOS / Linux):   sh stop.sh
# The report pages and the threat graph exports stay in output/site/ until: sh clean.sh
cd "$(dirname "$0")" || exit 1
docker info >/dev/null 2>&1 || { echo "Docker is not running, so there is nothing to stop. Start Docker Desktop and run this again to delete the review data."; exit 1; }
echo "Stopping both Dockers and deleting the review data..."
docker compose down -v --remove-orphans
docker compose -f target/docker-compose.yml --profile users down -v --remove-orphans
# versions before 1.3 kept the captured traffic and spans in these volumes on disk
docker volume rm atg_atg-capture atg_atg-telemetry >/dev/null 2>&1
echo
echo "Deleted: captured traffic, traces, Phase 1 files, EUJF/analysis JSON and the database."
echo "Kept:    output/site (report pages and the threat graph exports). Delete them with: sh clean.sh"
