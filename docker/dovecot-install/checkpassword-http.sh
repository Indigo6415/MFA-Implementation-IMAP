#!/bin/bash
set -e


REMOTE_IP="$1"    # remote client IP passed from Dovecot (%c)

# Read username & password from FD 3 (null-separated)
read -d $'\0' -r -u 3 USER
read -d $'\0' -r -u 3 PASS

# Debug (optional)
# echo "$(date) user=$USER pass=$PASS ip=$REMOTE_IP" >&2

# Perform IAM check
HTTP_CODE=$(curl --silent --show-error --max-time 5 -o /dev/null \
  -w "%{http_code}" \
  "http://host.docker.internal:8080/mfa?username=${USER}&password=${PASS}&ip=${REMOTE_IP}" \
  || true)

if [ "$HTTP_CODE" = "200" ]; then
    exec "$REPLY"
else
    exit 1
fi