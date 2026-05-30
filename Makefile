GO  ?= go
PKG ?= ./...
APP ?= ./cmd/goshield
BIN ?= bin/goshield

.PHONY: build fmt test check fix

build:
	$(GO) build -o $(BIN) $(APP)

fmt:
	$(GO) fmt $(PKG)

test:
	$(GO) test $(PKG)

fix:
	$(GO) fix $(PKG)

check: fmt test build