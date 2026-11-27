BINARY := tinmind
VERSION ?= $(shell cat VERSION)
LDFLAGS := -s -w -X github.com/bonjoski/tinmind/pkg/version.Version=$(VERSION)

.PHONY: build test vulncheck package clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/tinmind

test:
	go test -race -count=1 ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

package: clean
	mkdir -p dist
	for pair in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do \
		os=$${pair%/*}; arch=$${pair#*/}; \
		stage="dist/$(BINARY)_$(VERSION)_$${os}_$${arch}"; \
		mkdir -p "$$stage"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$stage/$(BINARY)" ./cmd/tinmind; \
		cp LICENSE README.md "$$stage/"; \
		tar -C dist -czf "dist/$(BINARY)_$(VERSION)_$${os}_$${arch}.tar.gz" "$(BINARY)_$(VERSION)_$${os}_$${arch}"; \
		rm -rf "$$stage"; \
	done
	cd dist && sha256sum *.tar.gz > checksums.txt

clean:
	rm -rf $(BINARY) dist
