package socks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

type AddrType byte

// Address types
const (
	IPV4   AddrType = 1
	DOMAIN AddrType = 3
	IPV6   AddrType = 4
)

type Cmd byte

// Commands
const (
	CONNECT Cmd = 1
	BIND    Cmd = 2
	UDP     Cmd = 3
)

// IntToBytes converts an int to its byte representation in big endian order
func IntToBytes(i uint16) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &i)

	return buf.Bytes()
}

// BytesToInt converts bytes in big endian order into its int representation
func BytesToInt(b []byte) uint16 {
	var port uint16
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.BigEndian, &port)

	return port
}

// Request represents the socks request or reply between the server and a client
type Request struct {
	Ver  byte     // Socks version
	Cmd  Cmd      // Command or reply
	Atyp AddrType // Address type
	Addr []byte   // Address
	Port []byte   // Port in big endian byte order
}

func (r Request) String() string {
	return fmt.Sprintf(
		"Ver: %d Cmd: %d Atyp: %d Addr: %s Port: %d",
		r.Ver, r.Cmd, r.Atyp, string(r.Addr), BytesToInt(r.Port))
}

// Marshal transforms the Request into its byte representation as specified by the RFC
func Marshal(r *Request) []byte {
	bytes := []byte{r.Ver, byte(r.Cmd), 0x0, byte(r.Atyp)}

	// First byte of address is the length in case of DOMAIN(?)
	if r.Atyp == DOMAIN {
		bytes = append(bytes, byte(len(r.Addr)))
	}
	bytes = append(bytes, r.Addr...)

	// Port is expected to be two bytes
	if len(r.Port) == 1 {
		r.Port = []byte{0, r.Port[0]}
	}
	return append(bytes, r.Port...)
}

// Unmarshal populates a new Request by reading bytes in the format specified by the RFC
func Unmarshal(b []byte) (Request, error) {
	var r Request

	if len(b) < 7 {
		return r, errors.New("Too few bytes to be a valid request")
	}

	r.Ver, r.Cmd, r.Atyp = b[0], Cmd(b[1]), AddrType(b[3])

	buf := bytes.NewBuffer(b[4:])
	addrLen := 0

	switch r.Atyp {
	case DOMAIN:
		baddrLen, err := buf.ReadByte()
		if err != nil {
			return r, errors.New("Missing address length")
		}
		addrLen = int(baddrLen)
	case IPV4:
		addrLen = 4
	case IPV6:
		addrLen = 16
	default:
		return r, errors.New("Unknown address type")
	}

	remaining := buf.Len() - 2 // Last two bytes are for port
	if remaining != addrLen {
		return r, errors.New(fmt.Sprintf("Invalid address length: %d, remaining bytes: %d", addrLen, remaining))
	}

	r.Addr = make([]byte, addrLen)
	if _, err := buf.Read(r.Addr); err != nil {
		return r, err
	}

	r.Port = make([]byte, 2)
	if _, err := buf.Read(r.Port); err != nil {
		return r, err
	}

	return r, r.Valid()
}

// Valid will do some basic validation of a Request
func (r *Request) Valid() error {
	if r.Ver != VERSION {
		return errors.New("Version not supported")
	}
	if r.Cmd != CONNECT {
		return errors.New("Command not understood")
	}
	if len(r.Addr) == 0 {
		return errors.New("Missing address")
	}
	if r.Atyp != IPV4 && r.Atyp != DOMAIN {
		return errors.New("Unsupported address type")
	}
	if len(r.Port) > 2 || (r.Port[0] == 0 && r.Port[1] == 0) {
		return errors.New("Invalid port number")
	}

	return nil
}

// WriteTo will Marshal and Write the result to provided writer
func (r *Request) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(Marshal(r))
	return int64(n), err
}

// NewReply constructs a new Request suitable for a reply to a previous Request from the client
func NewReply(status byte, ip net.IP, port uint16) *Request {
	var aType AddrType
	var addr []byte
	if len(ip) == 4 {
		aType = IPV4
		addr = ip.To4()
	} else {
		aType = IPV6
		addr = ip.To16()
	}

	reply := Request{
		Ver:  VERSION,
		Cmd:  0x0,   // Status
		Atyp: aType, // Our bind address
		Addr: addr,
		Port: IntToBytes(port)}

	return &reply
}
