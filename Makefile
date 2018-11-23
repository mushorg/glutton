VERSION := v1.0.0-pre
NAME := glutton
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := $(NAME) version $(VERSION)+$(BUILDSTRING)
BUILDDATE := $(shell date -u -Iseconds)

LDFLAGS := "-X \"main.VERSION=$(VERSIONSTRING)\" -X \"main.BUILDDATE=$(BUILDDATE)\""

.PHONY: all test clean build

default: build

build:
	go build -ldflags=$(LDFLAGS) -o bin/server app/server.go

static:
	go build --ldflags '-extldflags "-static"' -o bin/server app/server.go
	upx -1 bin/server

clean:
	rm -rf bin/

run: build
	sudo bin/server -i wlan0

docker:
	docker build -t glutton .
	docker run --cap-add=NET_ADMIN -it glutton
