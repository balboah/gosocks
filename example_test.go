package socks

import (
	"log"
	"net"
)

func ExampleServe() {
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
}
