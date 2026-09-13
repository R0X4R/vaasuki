FROM alpine:3.19

RUN apk add --no-cache busybox-extras && \
    adduser -D -s /bin/sh testuser && \
    echo "testuser:testpass" | chpasswd && \
    echo "root:toor" | chpasswd

EXPOSE 23

CMD ["busybox-extras", "telnetd", "-F", "-p", "23"]
