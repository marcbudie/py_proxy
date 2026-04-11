FROM haproxy:lts-alpine

COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg

EXPOSE 443

CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
