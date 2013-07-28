# Socks5 server

This is an implementation of a socks version 5 server (RFC 1928) written in Go.  
Currently supports CONNECT for IPv4 and IPv6.

Example:
```Go
ln, err := net.Listen("tcp", "9150")
if err != nil {
	log.Fatalln(err)
}

for {
	conn, err := ln.Accept()
	if err != nil {
		log.Print(err)
		continue
	}
	go func() {
		if err := Serve(conn); err != nil {
			log.Println(err)
		}
	}()
}
```