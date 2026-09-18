FROM alpine:3.19
RUN apk add --no-cache rsync && \
    mkdir -p /data/public /data/backup && \
    echo "Vaasuki Rsync Test Data" > /data/public/readme.txt

COPY rsyncd.conf /etc/rsyncd.conf
EXPOSE 873
CMD ["rsync", "--daemon", "--no-detach", "--config=/etc/rsyncd.conf"]
