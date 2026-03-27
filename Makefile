.PHONY: build test vet bench clean all cross

BINARY = jsecret
VERSION = 3.1.0
LDFLAGS = -ldflags="-s -w"

all: vet test build

build:
	go build $(LDFLAGS) -o $(BINARY)

test:
	go test ./... -v -count=1

vet:
	go vet ./...

bench:
	go test ./... -bench=. -benchmem -run=^$$ -count=1

clean:
	rm -f $(BINARY) $(BINARY).exe jsecret-*

cross: clean
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-linux-amd64
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-linux-arm64
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY)-windows-amd64.exe
