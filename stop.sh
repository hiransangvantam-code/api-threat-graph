#!/bin/sh
# Stop the API Threat Graph prototype (macOS / Linux).
cd "$(dirname "$0")" || exit 1
docker compose down
