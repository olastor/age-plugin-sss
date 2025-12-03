build:
	go build -ldflags "-X main.Version=$$(git describe --tags --always)" ./cmd/...

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix

clean:
	rm -f age-plugin-sss
