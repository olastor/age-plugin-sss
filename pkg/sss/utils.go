package sss

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
)

func compress(rawData []byte) (compressedData []byte, err error) {
	var gzipBuffer bytes.Buffer
	gz := gzip.NewWriter(&gzipBuffer)

	if _, err := gz.Write(rawData); err != nil {
		return nil, err
	}

	if err := gz.Close(); err != nil {
		return nil, err
	}

	return gzipBuffer.Bytes(), nil
}

func decompress(compressedData []byte) (rawData []byte, err error) {
	byteReader := bytes.NewReader(compressedData)
	gzipReader, err := gzip.NewReader(byteReader)

	if err != nil {
		return nil, err
	}

	rawData, err = ioutil.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}

	return
}

// add the X value to the share before it's passed to shamir.Combine()
func getShareWithX(share []byte, stanza *SSSStanza) (shareWithX []byte) {
	shareWithX = make([]byte, 17)

	// there's probably a better way to do this, but various attempts using slices failed.
	for i := 0; i < 16; i++ {
		shareWithX[i] = share[i]
	}

	shareWithX[16] = stanza.ShamirX

	return
}
