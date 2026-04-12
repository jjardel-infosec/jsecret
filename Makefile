.PHONY: build test vet bench clean all cross cover verify

BINARY = jsecret
VERSION = 4.0.1
LDFLAGS = -ldflags="-s -w"

all: vet test build

verify: vet test

build:
	go build $(LDFLAGS) -o $(BINARY)

test:
	go test ./... -v -count=1

vet:
	go vet ./...

bench:
	go test ./... -bench=. -benchmem -run=^$$ -count=1

cover:
	go test ./... -coverprofile=coverage.out -count=1
	go tool cover -func=coverage.out

clean:
	rm -f $(BINARY) $(BINARY).exe jsecret-* coverage.out

cross: clean
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-linux-amd64
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-linux-arm64
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-windows-amd64.exe
