package test

import (
	"fmt"
	"net"
	"testing"

	"github.com/qq2383/socks5"
)

func TestS5(t *testing.T) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", 10080))
	if err != nil {
		fmt.Println(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			break
		}

		go handle(conn)
	}
	fmt.Println("client end")
}

func handle(conn net.Conn) {
	defer conn.Close()

	s5 := socks5.New(conn)
	_, err := s5.AuthGetMethods()
	if err != nil {
		fmt.Println(err)
		return
	}
	s5.AuthRepies(socks5.AuthNone)

	host, port, atyp, err := s5.Requests()
	if err != nil {
		fmt.Printf("host: %s, port: %d\n", host, port)
		return
	}

	server, err := s5.Dial(host, port)
	if err != nil {
		fmt.Printf("host: %s, port: %d, %v\n", host, port, err)
		return
	}

	s5.Replies(socks5.ReplyPass, atyp, server.RemoteAddr())
	s5.Forward(server, conn)

}
