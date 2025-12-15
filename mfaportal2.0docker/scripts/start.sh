#!/bin/bash

echo "[start.sh] Booting container entrypoint..."

# Exim logs veilig zetten
mkdir -p /var/log/exim4
chown -R Debian-exim:Debian-exim /var/log/exim4 || true
chmod -R 750 /var/log/exim4 || true
touch /var/log/exim4/mainlog || true
chown Debian-exim:Debian-exim /var/log/exim4/mainlog || true
rm -f /var/log/exim4/paniclog || true

# Dovecot logbestand klaarzetten
touch /var/log/dovecot.log || true
chown dovecot:dovecot /var/log/dovecot.log || true
chmod 640 /var/log/dovecot.log || true

echo "[start.sh] Starting Exim4 (SMTP)..."
service exim4 start

echo "[start.sh] Starting Dovecot (IMAP)..."
service dovecot start

cd /opt/mfaportal || {
  echo "[start.sh] ERROR: /opt/mfaportal bestaat niet"
  sleep 3600
}

# DB initialiseren indien nodig
if [ ! -f mfa.db ]; then
  echo "[start.sh] Initialising mfa.db..."
  python3 -c "from app import init_db; init_db()" || echo "[start.sh] WARNING: DB init failed"
fi

# Zorg dat dovecot auth de DB kan lezen
chown root:dovecot /opt/mfaportal/mfa.db || true
chmod 640 /opt/mfaportal/mfa.db || true

echo "[start.sh] Starting Flask app..."
export FLASK_APP=app.py
python3 app.py &

# DB moet schrijfbaar zijn voor dovecot auth (UPDATE used_at + sqlite journal files)
chown root:dovecot /opt/mfaportal/mfa.db || true
chmod 660 /opt/mfaportal/mfa.db || true
chown root:dovecot /opt/mfaportal || true
chmod 775 /opt/mfaportal || true

# sqlite writes require directory writable for journal/temp files
chown root:dovecot /opt/mfaportal/mfa.db || true
chmod 660 /opt/mfaportal/mfa.db || true
chown root:dovecot /opt/mfaportal || true
chmod 775 /opt/mfaportal || true

# Cleanup elk uur: verwijder expired, of used waar grace voorbij is
(
  while true; do
    sqlite3 /opt/mfaportal/mfa.db "
      PRAGMA busy_timeout=5000;
      DELETE FROM app_passwords
      WHERE
        expires_at <= CURRENT_TIMESTAMP
        OR (used_at IS NOT NULL AND grace_until IS NOT NULL AND grace_until <= CURRENT_TIMESTAMP)
        OR (used_at IS NOT NULL AND grace_until IS NULL);
    " || true
    sleep 3600
  done
) &


echo "[start.sh] Tailing mail + dovecot logs..."
tail -F /var/log/exim4/mainlog /var/log/dovecot.log