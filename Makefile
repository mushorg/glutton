VERSION := v1.0.1
NAME := glutton
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := $(NAME) version $(VERSION)+$(BUILDSTRING)
BUILDDATE := $(shell date -u -Iseconds)

LDFLAGS := "-X \"main.VERSION=$(VERSIONSTRING)\" -X \"main.BUILDDATE=$(BUILDDATE)\""

.PHONY: all test clean build

.PHONY: tag
tag:
	git tag $(VERSION)
	git push origin --tags

.PHONY: upx
upx:
	cd bin; find . -type f -exec upx "{}" \;

default: build

build:
	go build -ldflags=$(LDFLAGS) -o bin/server app/server.go

static:
	go build --ldflags '-extldflags "-static"' -o bin/server app/server.go
	upx -1 bin/server

clean:
	rm -rf bin/

run: build
	sudo bin/server -c config.yaml

docker:
	docker build -t glutton .
	docker run --rm --cap-add=NET_ADMIN -it glutton

test:
	go test -v ./...
