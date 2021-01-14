GO=GO111MODULE=on go
GOBUILD=$(GO) build

all: build

build:
	$(GOBUILD) ./...

generate: specs/swagger-formatted.json
	$(GO) run github.com/go-swagger/go-swagger/cmd/swagger generate client --skip-validation -f $^ -t falcon

.PHONY: build generate

specs/swagger-formatted.json: specs/swagger.json
	jq '' $< > $@

specs/swagger.json:
	@echo "Sorry swagger.json needs to be obtained manually at this moment"
	@exit 1
