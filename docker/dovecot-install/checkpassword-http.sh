#!/bin/bash
set -e

REMOTE_IP="$1"
shift   # CRITICAL — removes %c so $@ is the backend command

IFS= read -r -d $'\0' -u 3 USER
IFS= read -r -d $'\0' -u 3 PASS

HTTP_CODE=$(curl --silent --show-error --max-time 5 -o /dev/null \
  -w "%{http_code}" \
  "http://host.docker.internal:8080/mfa?username=${USER}&password=${PASS}&ip=${REMOTE_IP}" \
  || true)

if [ "$HTTP_CODE" = "200" ]; then
    exec "$@"
else
    exit 1
fi