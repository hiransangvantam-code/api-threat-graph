#!/bin/sh
# Runs inside the curlimages/curl container on the system's network:  sh /kit/load.sh /kit/<id>/load.txt
# Each line of the file is "METHOD URL [JSON body]". A URL on atg-proxy:8080 goes through the sidecar
# as the system's front door; any other URL goes through the sidecar's forward proxy (atg-proxy:8081),
# so ATG sees calls made straight to a published service too. "ROUNDS n" repeats the list n times.
# No line logs in or sends a password: the load stays anonymous, except what the system's own load
# generator does.
f="$1"
rounds=$(sed -n 's/^ROUNDS *//p' "$f")
rounds=${rounds:-10}
i=0
while [ "$i" -lt "$rounds" ]; do
  grep -v -e '^#' -e '^ROUNDS' -e '^[[:space:]]*$' "$f" | while read -r method url body; do
    case "$url" in
      http://atg-proxy:8080*) px="" ;;
      *) px="-x http://atg-proxy:8081" ;;
    esac
    if [ -n "$body" ]; then
      curl -s -o /dev/null -m 15 -w '%{http_code}\n' $px -X "$method" -H 'Content-Type: application/json' --data "$body" "$url"
    else
      curl -s -o /dev/null -m 15 -w '%{http_code}\n' $px -X "$method" "$url"
    fi
  done
  i=$((i + 1))
done | sort | uniq -c | awk '{printf "  HTTP %s x%s\n", $2, $1}'
