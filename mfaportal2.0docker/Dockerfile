FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Basis packages + mail + debug tools
RUN apt-get update && apt-get install -y \
    exim4-daemon-light \
    dovecot-imapd dovecot-core \
    python3 python3-pip \
    python3-pam \
    libjpeg-dev zlib1g-dev \
    net-tools iproute2 inetutils-telnet \
    vim less sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# adduser configureren: HOME=/home en extra groep 'mail'
RUN sed -i 's|^HOME=.*|HOME=/home|' /etc/adduser.conf \
 && sed -i 's/^#\?ADD_EXTRA_GROUPS.*/ADD_EXTRA_GROUPS=1/' /etc/adduser.conf \
 && sed -i 's/^#\?EXTRA_GROUPS=.*/EXTRA_GROUPS="mail"/' /etc/adduser.conf

# Exim4 basisconfig kopiëren (CRLF → LF fixen) en config genereren
COPY config/exim/update-exim4.conf.conf /etc/exim4/update-exim4.conf.conf
RUN sed -i 's/\r$//' /etc/exim4/update-exim4.conf.conf \
 && update-exim4.conf \
 && mkdir -p /var/log/exim4 \
 && chown -R Debian-exim:Debian-exim /var/log/exim4 \
 && chmod -R 750 /var/log/exim4 \
 && touch /var/log/exim4/mainlog \
 && chown Debian-exim:Debian-exim /var/log/exim4/mainlog

# /var/mail rechten goed voor mbox + groep mail
RUN chown root:mail /var/mail && chmod 2775 /var/mail

# Dovecot config uit project kopiëren
COPY config/dovecot/10-auth.conf /etc/dovecot/conf.d/10-auth.conf
COPY config/dovecot/10-mail.conf /etc/dovecot/conf.d/10-mail.conf

# Dovecot logging naar /var/log/dovecot.log
RUN printf '\nlog_path = /var/log/dovecot.log\ninfo_log_path = /var/log/dovecot.log\n' >> /etc/dovecot/dovecot.conf

# App directory
WORKDIR /opt/mfaportal

# Python requirements
COPY app/requirements.txt /opt/mfaportal/
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Startscript
COPY scripts/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# App-password file voor Dovecot
RUN touch /etc/dovecot/app-passwd \
    && chown dovecot:dovecot /etc/dovecot/app-passwd \
    && chmod 640 /etc/dovecot/app-passwd

# Rest van de app code
COPY app/ /opt/mfaportal/

EXPOSE 25 143 5000

CMD ["/usr/local/bin/start.sh"]