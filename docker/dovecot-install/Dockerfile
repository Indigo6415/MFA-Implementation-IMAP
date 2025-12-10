# Use Ubuntu base
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Dovecot and dependencies + openssl for cert generation
RUN apt-get update && \
    apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d curl openssl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create mail user and maildir
RUN useradd -m vmail && mkdir -p /var/mail && chown -R vmail:vmail /var/mail

# Copy configuration
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY conf.d/ /etc/dovecot/conf.d/

# Copy checkpassword script
COPY checkpassword-http.sh /etc/dovecot/scripts/checkpassword-http.sh
RUN chmod +x /etc/dovecot/scripts/checkpassword-http.sh

# Generate self-signed certificate (for testing)
RUN mkdir -p /etc/ssl/certs /etc/ssl/private && \
    openssl req -new -x509 -days 365 \
    -nodes \
    -out /etc/ssl/certs/dovecot.pem \
    -keyout /etc/ssl/private/dovecot.pem \
    -subj "/CN=localhost"

RUN chmod 644 /etc/ssl/certs/dovecot.pem && chmod 600 /etc/ssl/private/dovecot.pem

# Expose IMAP/POP3 + SSL ports
EXPOSE 143 993 110 995

# Run Dovecot in foreground
CMD ["dovecot", "-F"]