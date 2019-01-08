FROM golang:1.11-alpine
RUN apk update
RUN apk add libnetfilter_queue-dev iptables-dev libpcap-dev

RUN mkdir -p $GOPATH/src/github.com/mushorg/glutton
WORKDIR $GOPATH/src/github.com/mushorg/glutton

RUN apk add g++ git make

RUN cd $WORKDIR
ENV GO111MODULE=on
ADD . .

RUN make build

RUN apk del g++ git make && rm -rf /var/cache/apk/*

CMD ["./bin/server", "-i", "eth0", "-l", "/var/log/glutton.log", "-d", "true"]
