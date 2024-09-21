build:
	go build -ldflags "-X main.Version=$$(git describe --tags --always)" ./cmd/...

clean:
	rm -f age-plugin-sss
