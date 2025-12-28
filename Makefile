build:
	go build -ldflags "-X main.Version=$$(git describe --tags --always)" ./cmd/...

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix

test: build
	go test -v ./...

test-e2e: build
	testscript ./testdata/*.txt

clean:
	rm -f age-plugin-sss
