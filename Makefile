
SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell date -Iseconds)
VERSION := $(or ${VERSION},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

CGO_ENABLED := 1
LINKMODE := -extldflags '-static -s -w'

all: test-opa test server

.PHONY: server
server:
	go build -tags netgo,osusergo,urfave_cli_no_docs \
		 -ldflags "$(LINKMODE) -X 'github.com/metal-stack/v.Version=$(VERSION)' \
								   -X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
								   -X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
								   -X 'github.com/metal-stack/v.BuildDate=$(BUILDDATE)'" \
	   -o bin/server github.com/metal-stack/api-server/cmd/server
	strip bin/server

.PHONY: test
test:
	go test ./... -race -coverprofile=coverage.out -covermode=atomic && go tool cover -func=coverage.out

.PHONY: test-opa
test-opa:
	make -C pkg/auth/policies test

.PHONY: lint-opa
lint-opa:
	make -C pkg/auth/policies lint

.PHONY: opa-fmt
opa-fmt:
	docker pull openpolicyagent/opa:latest-static
	docker run --rm -it --user $$(id -u):$$(id -g) -v $(PWD)/pkg/auth/policies:/work openpolicyagent/opa:latest-static fmt --v1-compatible --rego-v1 -w /work

.PHONY: golint
golint:
	golangci-lint run -p bugs -p unused -D protogetter

.PHONY: run
run:
	go run ./... cmd/server serve --log-level debug --stage dev

.PHONY: masterdata-up
masterdata-up:
	docker pull ghcr.io/metal-stack/masterdata-api || true
	docker network create metalstack || true
	docker run -d --name masterdatadb --network metalstack -e POSTGRES_PASSWORD="password" -e POSTGRES_USER="masterdata" -e POSTGRES_DB="masterdata" postgres:16-alpine
	sleep 5
	docker run -d --name masterdata-api -p 50051:50051 -e MASTERDATA_API_DBHOST=masterdatadb --network metalstack -v $(PWD)/certs:/certs ghcr.io/metal-stack/masterdata-api

.PHONY: masterdata-rm
masterdata-rm:
	docker rm -f masterdatadb masterdata-api
	docker network rm metalstack

.PHONY: auditing-up
auditing-up:
	docker run -d --name auditing -p 7700:7700 -e MEILI_MASTER_KEY=geheim getmeili/meilisearch:v1.6.2

.PHONY: auditing-rm
auditing-rm:
	docker rm -f auditing
