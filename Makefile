GO=GO111MODULE=on go
GOBUILD=$(GO) build

all: build

build:
	$(GOBUILD) ./...

generate: specs/swagger.json
	$(GO) run github.com/go-swagger/go-swagger/cmd/swagger generate client --skip-validation -f $^ -t falcon

.PHONY: build generate
