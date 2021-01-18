GO=GO111MODULE=on go
GOBUILD=$(GO) build

all: build

build:
	$(GOBUILD) ./...

generate: specs/swagger-download-patch.json
	$(GO) run github.com/go-swagger/go-swagger/cmd/swagger generate client --skip-validation -f $^ -t falcon

.PHONY: build generate

specs/swagger-formatted.json: specs/swagger.json
	jq '' $< > $@

specs/swagger-stripped-oauth.json: specs/swagger-formatted.json
	# We remove security info from swagger before generating golang API interface.
	# This achieves cleaner interface. OAuth is then applied automatically through the middle-ware.
	jq 'walk(if type == "object" and has("security") and (has("consumes") or has("produces")) then del(.security) else . end)' $< > $@

specs/swagger-download-patch.json: specs/swagger-stripped-oauth.json
	# We add missing binary response body spec to the swagger
	jq '.definitions."domain.DownloadItem"."type"="string" | .definitions."domain.DownloadItem"."format"="binary"' $< > $@

specs/swagger.json:
	@echo "Sorry swagger.json needs to be obtained manually at this moment"
	@exit 1
