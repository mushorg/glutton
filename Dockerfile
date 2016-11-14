FROM alpine:3.4
RUN apk update
RUN apk add conntrack-tools iptables
RUN mkdir -p /opt/glutton
WORKDIR /opt/glutton
ADD sensor .
ADD config/ports.yml .
CMD ["./sensor", "-conf", "ports.yml", "-set-tables"]
