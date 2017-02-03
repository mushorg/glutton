.PHONY: all test clean build

default: build

build:
	go build -o $$GOPATH/bin/server app/server.go

static:
	go build --ldflags '-extldflags "-static"' -o bin/server app/server.go
	upx -1 bin/server

clean:
	rm -rf bin/

run: build
	sudo ./bin/server -rules rules/rules.yaml

docker:
	docker build -t glutton .
	docker run --cap-add=NET_ADMIN -it glutton
