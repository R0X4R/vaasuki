FROM alpine:3.19

RUN apk add --no-cache vsftpd shadow && \
    adduser -D -s /bin/sh ftpuser && \
    echo "ftpuser:securepassword123" | chpasswd && \
    mkdir -p /var/ftp/pub && \
    echo "ServiceGuard anonymous verification probe test file" > /var/ftp/pub/test.txt && \
    chown -R ftp:ftp /var/ftp

ARG CONF_FILE=vsftpd-anon.conf
COPY ${CONF_FILE} /etc/vsftpd/vsftpd.conf

EXPOSE 21 21100-21115
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
