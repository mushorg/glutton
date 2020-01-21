FROM golang:1.13-alpine
RUN apk update
RUN apk add libnetfilter_queue-dev iptables-dev libpcap-dev

RUN mkdir -p /opt/glutton
WORKDIR /opt/glutton

RUN apk add g++ git make

RUN cd $WORKDIR
ENV GO111MODULE=on

# Fetch dependencies
COPY go.mod ./
RUN go mod download

ADD . .

RUN make build

# FIXME: (enable) RUN apk del g++ git make && rm -rf /var/cache/apk/*

CMD ["./bin/server", "-i", "eth0", "-l", "/var/log/glutton.log", "-d", "true"]
