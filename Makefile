VERSION := v1.0.1
NAME := glutton
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := $(NAME) version $(VERSION)+$(BUILDSTRING)
BUILDDATE := $(shell date -u -Iseconds)

LDFLAGS := "-X \"main.VERSION=$(VERSIONSTRING)\" -X \"main.BUILDDATE=$(BUILDDATE)\""

.PHONY: all test clean build deploy deploy-helper

.PHONY: tag
tag:
	git tag $(VERSION)
	git push origin --tags

.PHONY: upx
upx:
	cd bin; find . -type f -exec upx "{}" \;

default: build

build:
	CC=clang-17 CXX=clang++-17 go build -ldflags=$(LDFLAGS) -o bin/server app/server.go

.PHONY: spicy
spicy:
	cd protocols/spicy && make

static:
	go build --ldflags '-extldflags "-static"' -o bin/server app/server.go
	upx -1 bin/server

# Local-only deploy target; see .env.deploy.example (file is gitignored).
-include .env.deploy

.require-deploy-host:
	@test -n "$(DEPLOY_HOST)" || (echo 'DEPLOY_HOST unset; copy .env.deploy.example to .env.deploy' >&2; exit 1)

# One-time: install scripts/redeploy-glutton.sh on the honeypot host.
deploy-helper: .require-deploy-host
	scp scripts/redeploy-glutton.sh $(DEPLOY_HOST):/opt/glutton/redeploy-glutton.sh
	ssh $(DEPLOY_HOST) 'chmod +x /opt/glutton/redeploy-glutton.sh'

# Build, upload to /tmp (avoids ETXTBSY), then restart the screen session.
deploy: clean build .require-deploy-host
	scp bin/server $(DEPLOY_HOST):/tmp/glutton.new
	scp config/rules.yaml $(DEPLOY_HOST):/opt/glutton/rules.yaml
	ssh $(DEPLOY_HOST) /opt/glutton/redeploy-glutton.sh

clean:
	rm -rf bin/

run: build
	sudo bin/server

docker:
	docker build --progress=plain -t glutton .
	docker run --rm --cap-add=NET_ADMIN -it --name glutton glutton 

test: spicy
	go test -v ./...
