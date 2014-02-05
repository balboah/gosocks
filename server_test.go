package socks

import (
	"bytes"
	"io"
	"testing"
)

type nopCloser struct {
	io.ReadWriter
}

func (nopCloser) Close() error { return nil }

func TestHandshake(t *testing.T) {
	socks := SocksConn{ReadWriteCloser: &nopCloser{&bytes.Buffer{}}}

	socks.Write([]byte{VERSION, 0x4, 0x3, 0x2, 0x1, 0x0})
	socks.Handshake()

	response := make([]byte, 2)
	socks.Read(response)

	if bytes.Compare(response, []byte{VERSION, 0x0}) != 0 {
		t.Errorf("Expected server to pick method '0', got: %v", response)
	}
}

func TestRequest(t *testing.T) {
	socks := SocksConn{ReadWriteCloser: &nopCloser{&bytes.Buffer{}}}

	socks.HandleRequest()
}
