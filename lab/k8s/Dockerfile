FROM nginx:alpine
RUN apk add --no-cache openssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/key.pem -out /etc/nginx/cert.pem \
    -subj "/CN=kubernetes.default.svc"
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 6443 8443
