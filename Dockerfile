FROM golang:1.9-alpine
RUN apk update
RUN apk add libnetfilter_queue-dev iptables-dev libpcap-dev

RUN mkdir -p $GOPATH/src/github.com/mushorg/glutton
WORKDIR $GOPATH/src/github.com/mushorg/glutton

RUN apk add g++ git

ADD . .

RUN go build -o server app/server.go && \
    apk del g++ git && \
    rm -rf /var/cache/apk/*

CMD ["./server", "-i", "eth0"]
