#!/bin/sh
# Delete EVERYTHING the last review left on this computer (macOS / Linux):   sh clean.sh
# Use it after the report has been handed over. Add --yes to skip the question.
cd "$(dirname "$0")" || exit 1
echo "This deletes all data of the last review: the report pages and threat graph exports in"
echo "output/, and any Docker data still there. Copy output/site somewhere first if you need it."
if [ "$1" != "--yes" ]; then
  printf "Type YES to delete: "
  read -r ok
  [ "$ok" = "YES" ] || [ "$ok" = "yes" ] || { echo "Nothing deleted."; exit 1; }
fi
if docker info >/dev/null 2>&1; then
  docker compose down -v --remove-orphans >/dev/null 2>&1
  docker compose -f target/docker-compose.yml --profile users down -v --remove-orphans >/dev/null 2>&1
  for f in companies/*/docker-compose.yml opensource/*/docker-compose.yml; do docker compose -f "$f" --profile users down -v --remove-orphans >/dev/null 2>&1; done
  docker volume rm atg_atg-capture atg_atg-telemetry >/dev/null 2>&1
else
  echo "(Docker is not running, so its data could not be checked. Run this again once Docker is running.)"
fi
if [ -d output ]; then
  # files written by the container can belong to root on Linux; remove them through Docker if needed
  rm -rf output 2>/dev/null || docker run --rm -v "$PWD/output:/o" api-threat-graph:1.6 sh -c 'rm -rf /o/* /o/.[!.]*' && rm -rf output
fi
[ -d output ] && { echo "Could not delete output/. Delete that folder by hand."; exit 1; }
echo "Done. No data of the review is left in this folder or in Docker."
