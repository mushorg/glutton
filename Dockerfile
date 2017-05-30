FROM golang:1.7.4-alpine3.5
RUN apk update
RUN apk add libnetfilter_queue-dev iptables-dev libpcap-dev

RUN mkdir -p $GOPATH/src/github.com/mushorg/glutton
WORKDIR $GOPATH/src/github.com/mushorg/glutton
ADD . .
RUN apk add g++ glide git && \
    glide install && \
    glide update && \
    mkdir -p bin/ && \
    go build -o bin/server app/server.go && \
    apk del g++ glide git && \
    rm -rf /var/cache/apk/*

# RUN mkdir -p /opt/glutton
# WORKDIR /opt/glutton
# ADD bin/server .
# ADD rules/rules.yaml .
CMD ["bin/server", "-interface", "eth0"]
