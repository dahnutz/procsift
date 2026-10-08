BINARY := bin/procsift
VERSION := 0.5.1
RELEASE_GO_VERSION := go1.27.1

.PHONY: build test test-live verify-binary release-check clean

# CGO_ENABLED=0 avoids a host libc dependency. Disabling VCS stamping makes
# the binary reproducible from the same source after exporting without .git.
build:
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) ./cmd/procsift

test:
	CGO_ENABLED=0 go test ./...

test-live:
	PROCSIFT_LIVE_TEST=1 CGO_ENABLED=0 go test ./internal/collect -run TestLiveCollectSmoke -count=1

# Rebuild with this toolchain and compare the distributed binary byte for byte.
verify-binary:
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o "$$tmp" ./cmd/procsift; \
	cmp -s "$$tmp" $(BINARY) || { echo "$(BINARY) differs from a current source build" >&2; exit 1; }

# The public artifact is only ready after the source, docs, and binary are
# committed together and the exact build can be reproduced.
release-check:
	@git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "release-check requires a Git checkout" >&2; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "working tree is not clean" >&2; exit 1; }
	@test "$$(go env GOVERSION)" = "$(RELEASE_GO_VERSION)" || { echo "release build requires $(RELEASE_GO_VERSION)" >&2; exit 1; }
	@$(MAKE) test
	@$(MAKE) verify-binary

clean:
	rm -rf bin
