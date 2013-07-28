package socks

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMarshalUnmarshalDomain(t *testing.T) {
	b := []byte{
		VERSION,       // Socks version
		byte(CONNECT), // Command
		0x0,           // Reserved
		byte(DOMAIN),  // Addr type
		0x9,           // Addr length
	}
	b = append(b, []byte("google.se")...) // Destination Addr
	b = append(b, 0, 80)                  // Port

	r, err := Unmarshal(b)
	if err != nil {
		t.Error(err)
	}
	if r.Ver != VERSION {
		t.Error("Invalid socks version:", r.Ver)
	}
	if r.Cmd != CONNECT {
		t.Error("Invalid cmd:", r.Cmd)
	}
	if r.Atyp != DOMAIN {
		t.Error("Invalid atyp:", r.Atyp)
	}
	if !bytes.Equal(r.Addr, []byte("google.se")) {
		t.Error("Invalid addr:", string(r.Addr))
	}

	m := Marshal(&r)
	if bytes.Equal(m, b) != true {
		t.Logf("Original:\n%s\n", hex.Dump(b))
		t.Logf("Marshalled:\n%s\n", hex.Dump(m))
		t.Error("Marshalled bytes does not match original bytes")
	}
}

func TestMarshallUnmarshalIP(t *testing.T) {
	b := []byte{
		VERSION,            // Socks version
		byte(CONNECT),      // Command
		0x0,                // Reserved
		byte(IPV4),         // Addr type
		0x8, 0x8, 0x8, 0x8, // IPv4 address
		0x0, 0x80, // Port
	}

	r, err := Unmarshal(b)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(r.Addr, []byte{0x8, 0x8, 0x8, 0x8}) {
		t.Error("Invalid addr:", r.Addr)
	}
}

func TestIntToBytesToInt(t *testing.T) {
	b := []byte{0, 80}
	i := uint16(80)
	r := IntToBytes(i)
	if !bytes.Equal(r, b) {
		t.Logf("%v != %v", b, r)
		t.Error("Bytes not equal for port 80")
	}

	if BytesToInt(r) != i {
		t.Error("Could not convert bytes back to int")
	}
}
