.PHONY: all test clean build

default: build

build:
	@mkdir -p bin/
	go build -o bin/sensor app/server.go
	upx -1 bin/sensor

clean:
	rm -rf bin/

run: build
	sudo ./bin/sensor -rules rules/rules.yaml

docker: build
	docker build -t glutton .
	docker run --cap-add=NET_ADMIN -it glutton
