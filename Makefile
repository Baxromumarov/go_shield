GO ?= go
PKG ?= ./...

.PHONY: build fmt test check

build:
	$(GO) build $(PKG)

fmt:
	gofmt -w .

test:
	$(GO) test $(PKG)

check: fmt test build

fix:
	go fix ./...