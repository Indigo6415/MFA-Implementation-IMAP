FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    dovecot-lmtpd \
    dovecot-sieve \
    dovecot-managesieved \
    ca-certificates \
    curl \
    ssl-cert \
    && rm -rf /var/lib/apt/lists/*

# vmail user
RUN groupadd -g 5000 vmail \
    && useradd -u 5000 -g vmail -d /var/mail vmail \
    && mkdir -p /var/mail/vhosts \
    && chown -R vmail:vmail /var/mail

COPY conf/ /etc/dovecot/

EXPOSE 143 993

CMD ["/usr/sbin/dovecot", "-F"]