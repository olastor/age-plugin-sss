package sss

import (
	"bytes"
	"testing"
)

func TestDecompressLimit(t *testing.T) {
	// Build a gzip stream that expands to more than maxDecompressedSize bytes.
	payload := bytes.Repeat([]byte{0}, maxDecompressedSize+1)
	compressed, err := compress(payload)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	_, err = decompress(compressed)
	if err == nil {
		t.Fatalf("decompress succeeded for payload larger than %d bytes", maxDecompressedSize)
	}
}
