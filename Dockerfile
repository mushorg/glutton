FROM golang:1.23-alpine AS build-env
RUN apk update
RUN apk add g++ git make iptables-dev libpcap-dev

RUN mkdir -p /opt/glutton
WORKDIR /opt/glutton

RUN cd $WORKDIR

ADD . .

RUN make build

# run container
FROM alpine:3.19

RUN apk add iptables iptables-dev libpcap-dev
WORKDIR /opt/glutton

COPY --from=build-env /opt/glutton/bin/server /opt/glutton/bin/server
COPY --from=build-env /opt/glutton/config /opt/glutton/config
COPY --from=build-env /opt/glutton/rules /opt/glutton/rules

CMD ["./bin/server", "-i", "eth0", "-l", "/var/log/glutton.log", "-d", "true"]
