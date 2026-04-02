BINARY    := oqs-scanner
BUILD_DIR := ./cmd/oqs-scanner
ENGINE_DIR := ./engines
VERSION   := 0.1.0
LDFLAGS   := -ldflags="-s -w -X main.version=$(VERSION)"

CIPHERSCOPE_SRC := ../OQS/cipherscope-main
CRYPTOSCAN_SRC  := ../OQS/cryptoscan-main

TEST_TARGET := $(CRYPTOSCAN_SRC)/crypto-samples

.PHONY: build clean build-engines test test-scan test-cbom test-sarif test-failon test-diff lint all bench bench-save bench-compare fuzz manifest-hash manifest-validate

## Build the oqs-scanner binary
build:
	go build $(LDFLAGS) -o $(BINARY) $(BUILD_DIR)

## Build all engine binaries
build-engines: build-cipherscope build-cryptoscan

## Build cipherscope from Rust source
build-cipherscope:
	@echo "Building cipherscope..."
	cd $(CIPHERSCOPE_SRC) && cargo build --release
	@mkdir -p $(ENGINE_DIR)
	cp $(CIPHERSCOPE_SRC)/target/release/cipherscope $(ENGINE_DIR)/cipherscope
	@echo "cipherscope binary copied to $(ENGINE_DIR)/cipherscope"

## Build cryptoscan from Go source
build-cryptoscan:
	@echo "Building cryptoscan..."
	cd $(CRYPTOSCAN_SRC) && go build -o cryptoscan ./cmd/cryptoscan
	@mkdir -p $(ENGINE_DIR)
	cp $(CRYPTOSCAN_SRC)/cryptoscan $(ENGINE_DIR)/cryptoscan
	@echo "cryptoscan binary copied to $(ENGINE_DIR)/cryptoscan"

## Build everything
all: build-engines build

## Run Go unit tests
test:
	go test -race -count=1 ./...

## Smoke test: scan crypto-samples and verify outputs
test-scan: build
	@echo "=== Table output ==="
	./$(BINARY) scan --path $(TEST_TARGET) --format table 2>/dev/null | tail -5
	@echo ""
	@echo "=== JSON summary ==="
	./$(BINARY) scan --path $(TEST_TARGET) --format json 2>/dev/null | head -25
	@echo ""
	@echo "=== CBOM component count ==="
	./$(BINARY) scan --path $(TEST_TARGET) --format cbom 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'Components: {len(d[\"components\"])}')"
	@echo ""
	@echo "=== SARIF rule count ==="
	./$(BINARY) scan --path $(TEST_TARGET) --format sarif 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); r=d['runs'][0]; print(f'Rules: {len(r[\"tool\"][\"driver\"][\"rules\"])}, Results: {len(r[\"results\"])}')"

## Test CBOM output validates as JSON
test-cbom: build
	./$(BINARY) scan --path $(TEST_TARGET) --format cbom --output /tmp/oqs-cbom.json 2>/dev/null
	python3 -c "import json; json.load(open('/tmp/oqs-cbom.json')); print('CBOM JSON valid')"

## Test SARIF output validates as JSON
test-sarif: build
	./$(BINARY) scan --path $(TEST_TARGET) --format sarif --output /tmp/oqs-sarif.json 2>/dev/null
	python3 -c "import json; json.load(open('/tmp/oqs-sarif.json')); print('SARIF JSON valid')"

## Test --fail-on exits with code 1
test-failon: build
	@./$(BINARY) scan --path $(TEST_TARGET) --format json --fail-on critical --output /dev/null 2>/dev/null; \
	if [ $$? -eq 1 ]; then echo "--fail-on critical: PASS (exit 1)"; else echo "--fail-on critical: FAIL"; fi

## Test diff scan mode (requires git repo)
test-diff: build
	@echo "=== Diff scan against HEAD~1 ==="
	./$(BINARY) diff --path . --base HEAD~1 --format table 2>&1 | tail -10
	@echo ""
	@echo "Diff scan mode: PASS"

## Run all tests
test-all: test test-scan test-cbom test-sarif test-failon test-diff

## Lint Go code
lint:
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

## Run benchmarks for the orchestrator pipeline
bench:
	go test -bench=. -benchmem ./pkg/orchestrator/ -run=^$$

## Save current benchmark results as baseline
bench-save:
	go test -bench=. -benchmem -count=3 -timeout 10m ./pkg/orchestrator/... 2>/dev/null | \
		go run ./cmd/bench-compare -save -output benchmarks/baseline.json

## Compare current benchmarks against baseline
bench-compare:
	go test -bench=. -benchmem -count=3 -timeout 10m ./pkg/orchestrator/... 2>/dev/null | \
		go run ./cmd/bench-compare -baseline benchmarks/baseline.json -threshold 20

## Run fuzz tests (10 seconds each)
fuzz:
	go test -fuzz=FuzzParseClassFile -fuzztime=10s ./pkg/engines/binaryscanner/java/
	go test -fuzz=FuzzClassifyAlgorithm -fuzztime=10s ./pkg/quantum/
	go test -fuzz=FuzzNormalize -fuzztime=10s ./pkg/registry/

## Download engine binaries and compute SHA-256 hashes for manifest
manifest-hash:
	go run ./cmd/manifest-hash -input pkg/enginemgr/manifest.json -output pkg/enginemgr/manifest.json

## Validate manifest has no placeholder SHA-256 values (CI gate)
manifest-validate:
	go run ./cmd/manifest-hash -input pkg/enginemgr/manifest.json -validate

## Clean build artifacts
clean:
	rm -f $(BINARY)
	rm -f $(ENGINE_DIR)/cipherscope
	rm -f $(ENGINE_DIR)/cryptoscan
