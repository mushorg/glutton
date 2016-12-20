.PHONY: all test clean build

build:
	GOOS=linux go build -o sensor server/glutton_server.go

run: build
	sudo ./sensor -conf config/ports.yml

docker: build
	docker build -t glutton .
	docker run --cap-add=NET_ADMIN -it glutton
