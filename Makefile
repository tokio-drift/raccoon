GO ?= go
PCAP ?= testdata/tcp_basic.pcap
BIN := bin/raccoon

.PHONY: all build test fmt vet check ui run testdata bench lab clean

all: check

build:
	$(GO) build -o $(BIN) ./cmd/raccoon

test:
	$(GO) test ./...

fmt:
	gofmt -s -w .

vet:
	$(GO) vet ./...

check:
	@unformatted=$$(gofmt -s -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt required for:"; echo "$$unformatted"; exit 1; \
	fi
	$(GO) vet ./...
	$(GO) test ./...

ui:
	@if [ -f web/package.json ]; then \
		cd web && npm ci && npm run build; \
	else \
		echo "web/package.json not found; frontend not scaffolded yet, skipping UI build"; \
	fi

run: build
	$(BIN) analyze $(PCAP)

testdata:
	$(GO) run ./testdata/gen

bench:
	$(GO) test ./... -bench . -benchmem -run '^$$'

lab:
	@echo "lab target is implemented in PLUS-H"

clean:
	rm -rf bin
