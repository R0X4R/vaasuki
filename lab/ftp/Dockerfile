FROM alpine:3.19

RUN apk add --no-cache vsftpd && \
    adduser -D -s /bin/sh ftpuser && \
    echo "ftpuser:securepassword123" | chpasswd && \
    mkdir -p /var/ftp/pub && \
    chmod 555 /var/ftp && \
    chmod 755 /var/ftp/pub && \
    echo "Vaasuki anonymous verification probe test file" > /var/ftp/pub/test.txt && \
    chown -R ftp:ftp /var/ftp/pub

ARG CONF_FILE=vsftpd-anon.conf
COPY ${CONF_FILE} /etc/vsftpd/vsftpd.conf

EXPOSE 21 21100-21115
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
