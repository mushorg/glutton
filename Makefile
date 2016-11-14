build:
	CGO_ENABLED=0 GOOS=linux go build -o sensor glutton/glutton_server.go

run: build
	sudo ./sensor -conf config/ports.yml

docker: build
	docker build -t glutton .
	docker run --cap-add=NET_ADMIN -it glutton
