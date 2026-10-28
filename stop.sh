#!/bin/sh
# Stop both Dockers (macOS / Linux). The pages of the last run stay in output/site/.
cd "$(dirname "$0")" || exit 1
docker compose down
docker compose -f target/docker-compose.yml --profile users down
