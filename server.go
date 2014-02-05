// Package socks implements a socks version 5 server (RFC 1928).
// Currently supports CONNECT for IPv4 and IPv6.
package socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// The socks version that we support
const VERSION = 0x5

// SocksConn represents the client connection that we should read and reply Requests to
type SocksConn struct {
	io.ReadWriteCloser
	Dialer
}

// Handshake is the first step
// here we negotiate available authentication methods and verify the protocol version
func (s *SocksConn) Handshake() error {
	buf := make([]byte, 2)
	s.Read(buf)

	ver, nmethods := buf[0], buf[1]
	if ver != VERSION {
		return errors.New("Invalid socks version specified by client")
	}

	if nmethods > 255 {
		return errors.New("Too many methods specified")
	}

	buf = make([]byte, nmethods)
	if nread, err := s.Read(buf); err != nil {
		return err
	} else {
		// Look through methods to find one that suits us
		for b := range buf[:nread] {
			if b == 0x0 {
				if _, err := s.Write([]byte{VERSION, 0x0}); err != nil {
					return err
				}
				return nil
			}
		}
	}

	return errors.New("Could not find a suitable method for authentication")
}

// FailHandshake is ran when we want to tell the client we did not understand their Handshake
func (s *SocksConn) FailHandshake() {
	s.Write([]byte{VERSION, 0xFF})
}

// FailRequest is a generic request failure reply
func (s *SocksConn) FailRequest() {
	s.Write(Marshal(
		&Request{Ver: VERSION, Cmd: 0x1, Atyp: 0x0, Addr: []byte{0x0}, Port: []byte{0x0, 0x0}}))
}

// HandleRequest reads the request and issues the requested command.
// Currently only CONNECT is implemented.
func (s *SocksConn) HandleRequest() error {
	buf := make([]byte, 261)
	nread, err := io.ReadAtLeast(s, buf, 4)
	if err != nil {
		return err
	}
	buf = buf[:nread]

	r, err := Unmarshal(buf)
	if err != nil {
		return err
	}

	switch r.Cmd {
	case CONNECT:
		if err := s.Dial(r.Addr, r.Atyp, r.Port); err != nil {
			return err
		}
	}

	return nil
}

type Dialer interface {
	Dial([]byte, AddrType, []byte) error
}

type defaultDialer struct {
	client io.ReadWriteCloser
}

// Dial will connect to an address of specified type (IPV4 or 6) on behalf of the client.
// Writes and reads are copied between the client and the new connection until EOF of either end.
func (d defaultDialer) Dial(addr []byte, aTyp AddrType, port []byte) error {
	sport := strconv.Itoa(int(BytesToInt(port)))
	var saddr string

	switch aTyp {
	case DOMAIN:
		saddr = string(addr)
	case IPV4:
		saddr = net.IP(addr).String()
	case IPV6:
		saddr = fmt.Sprintf("[%s]", net.IP(addr))
	}
	dialstring := fmt.Sprintf("%s:%s", saddr, sport)

	conn, err := net.DialTimeout("tcp", dialstring, 30*time.Second)
	if err != nil {
		return err
	}

	laddr := conn.LocalAddr().(*net.TCPAddr)
	if err != nil {
		return err
	}

	if _, err := NewReply(0x0, laddr.IP, uint16(laddr.Port)).WriteTo(d.client); err != nil {
		return err
	}

	done := make(chan bool)
	go func() {
		io.Copy(d.client, conn)
		d.client.Close()
		done <- true
	}()

	io.Copy(conn, d.client)
	conn.Close()
	<-done

	return nil
}

// Serve will Handshake and HandleRequest for an established net.Conn
// or any other implementation of io.ReadWriteCloser. Connections will be proxied using specified
// dialer.
func Serve(c io.ReadWriteCloser, d Dialer) error {
	defer c.Close()

	if d == nil {
		d = defaultDialer{c}
	}
	sock := SocksConn{c, d}

	if err := sock.Handshake(); err != nil {
		sock.FailHandshake()
		return err
	}

	if err := sock.HandleRequest(); err != nil {
		sock.FailRequest()
		return err
	}

	return nil
}
