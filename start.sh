#!/bin/sh
# Start the API Threat Graph prototype with Docker and open it in the browser (macOS / Linux).
#   sh start.sh
cd "$(dirname "$0")" || exit 1
command -v docker >/dev/null 2>&1 || { echo "Docker is not installed. Get Docker Desktop: https://www.docker.com/products/docker-desktop/"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop, wait until it says 'Engine running', then run this again."; exit 1; }

PORT="${ATG_PORT:-8080}"
URL="http://localhost:$PORT/"
echo "Building and starting. The first time downloads about 300 MB and takes a few minutes."
docker compose up --build -d || exit 1

printf "Waiting for %s " "$URL"
i=0
until curl -s -o /dev/null "$URL"; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then echo; echo "The page did not come up. Log:"; docker compose logs --tail 60 atg; exit 1; fi
  printf "."
  sleep 2
done
echo
case "$(uname)" in
  Darwin) open "$URL" ;;
  *) command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL" >/dev/null 2>&1 ;;
esac
echo "Opened $URL  (the threat graph appears after about a minute)"
echo "Stop everything with: sh stop.sh    (Ctrl+C below only stops the log)"
echo
docker compose logs -f --tail 20 atg
