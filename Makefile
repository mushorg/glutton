build:
	mkdir -p build
	CGO_ENABLED=0 GOOS=linux go build -o build/sensor server/glutton_server.go

run: build
	sudo build/sensor -conf config/ports.yml

docker: build
	docker build -t glutton .
	docker run --cap-add=NET_ADMIN -it glutton

build-raw:
	mkdir -p build
	CGO_ENABLED=0 GOOS=linux go build -o build/raw-sensor server/raw_server.go

run-raw: build-raw
	sudo build/raw-sensor

docker-raw:
	docker build -t glutton-raw -f ./Dockerfile-raw .
	docker run --cap-add=NET_ADMIN -it glutton-raw
