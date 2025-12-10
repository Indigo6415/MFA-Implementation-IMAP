FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Dovecot and dependencies
RUN apt-get update && \
    apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create mail user
RUN useradd -m vmail && mkdir -p /var/mail && chown -R vmail:vmail /var/mail

# Copy Dovecot config
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY conf.d/ /etc/dovecot/conf.d/

# Copy checkpassword script
COPY checkpassword-http.sh /etc/dovecot/scripts/checkpassword-http.sh
RUN chmod +x /etc/dovecot/scripts/checkpassword-http.sh

# Expose IMAP/POP3 ports
EXPOSE 143 993 110 995

# Run Dovecot in foreground
CMD ["dovecot", "-F"]