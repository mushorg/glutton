FROM golang:1.7.4-alpine3.5
RUN apk update
RUN apk add libnetfilter_queue-dev iptables-dev libpcap-dev

RUN mkdir -p $GOPATH/src/github.com/mushorg/glutton
WORKDIR $GOPATH/src/github.com/mushorg/glutton
ADD . .
RUN apk add g++

RUN mkdir -p bin/
RUN go build -o bin/server app/server.go

# RUN mkdir -p /opt/glutton
# WORKDIR /opt/glutton
# ADD bin/server .
# ADD rules/rules.yaml .
CMD ["bin/server", "-interface", "eth0"]
