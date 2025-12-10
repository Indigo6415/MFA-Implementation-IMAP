#!/bin/bash
set -e

REPLY="$1"  # Path to checkpassword‑reply helper

# Read username/password from fd 3 (null-separated)
read -d $'\0' -r -u 3 USER
read -d $'\0' -r -u 3 PASS

# Log or debug (optional)
# echo "$(date) AUTH attempt user=$USER" >&2

# Perform your IAM HTTP request
HTTP_CODE=$(curl --silent --show-error --max-time 5 -o /dev/null -w "%{http_code}" \
  "http://host.docker.internal:8080/mfa?username=${USER}&password=${PASS}" || true)

if [ "$HTTP_CODE" = "200" ]; then
  # Optionally export userdb fields:
  # export user="$USER"
  # export uid=vmail
  # export gid=vmail
  # export home=/var/mail/$USER
  exec "$REPLY"
else
  exit 1
fi