FROM alpine:3.19

RUN apk add --no-cache samba && \
    mkdir -p /shares/public && \
    echo "ServiceGuard SMB Guest Share Probe File" > /shares/public/test.txt && \
    chmod -R 0777 /shares/public

COPY smb.conf /etc/samba/smb.conf

EXPOSE 445 139

CMD ["smbd", "-F", "--no-process-group", "-s", "/etc/samba/smb.conf"]
