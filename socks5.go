package socks5

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Socket version number
const (
	VER byte = 0x05
)

// The values currently defined for METHOD are:
// AuthNone: NO AUTHENTICATION REQUIRED
// AuthUser: USERNAME/PASSWORD
// ReplyPass: The identity authentication is passed
// ReplyFail: Authentication failed
const (
	AuthNone  byte = 0x00
	AuthUser  byte = 0x02
	ReplyPass byte = 0x00
	ReplyFail byte = 0x01
)

// Request atyp value
const (
	BIND          byte = 0x02
	CONNECT       byte = 0x01
	DomainName    byte = 0x03
	IPv4          byte = 0x01
	IPv6          byte = 0x04
	UDP_ASSOCIATE byte = 0x03
)

// The error code are:
// ErrVer: Version not 5
// ErrConnect: Methods only support connect
// ErrAuthFail: The username or password is incorrectly authenticated
var (
	ErrVer      = errors.New("version not 5")
	ErrConnect  = errors.New("this server only support cmd is 0x01")
	ErrAuthFail = fmt.Errorf("authentication failed")
)

// Socks5 struct
type Socks5 struct {
	r *bufio.Reader
	w *bufio.Writer
}

// New Socks5 func
func New(conn net.Conn) *Socks5 {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	return &Socks5{r: r, w: w}
}

// How to obtain the authentication
func (s *Socks5) AuthGetMethod() (byte, error) {
	err := s.GetVer()
	if err != nil {
		return 0, err
	}

	return s.r.ReadByte()
}

// Obtain the authentication method, return methods
func (s *Socks5) AuthGetMethods() ([]byte, error) {
	err := s.GetVer()
	if err != nil {
		return nil, err
	}

	nmethods, err := s.r.ReadByte()
	if err != nil {
		return nil, err
	}

	p := make([]byte, int(nmethods))
	n, err := s.r.Read(p)
	if err != nil {
		return nil, err
	}

	return p[:n], err
}

// Obtain the authentication status
// If the error parameter is set to nil, the authentication is passed
// otherwise the authentication fails
func (s *Socks5) AuthGetStatus() error {
	err := s.GetVer()
	if err != nil {
		return err
	}

	status, err := s.r.ReadByte()
	if err != nil {
		return err
	}
	if status != ReplyPass {
		return ErrAuthFail
	}
	return nil
}

// Obtain an authenticated user, return user name and passwd
func (s *Socks5) AuthGetUser() (user, passwd string, err error) {
	err = s.GetVer()
	if err != nil {
		return user, passwd, err
	}

	ulen, err := s.r.ReadByte()
	if err != nil {
		return user, passwd, err
	}
	p := make([]byte, int(ulen))
	n, err := s.r.Read(p)
	if err != nil {
		return user, passwd, err
	}
	user = string(p[:n])

	plen, err := s.r.ReadByte()
	if err != nil {
		return user, passwd, err
	}
	p = make([]byte, int(plen))
	n, err = s.r.Read(p)
	if err != nil {
		return "", "", err
	}
	passwd = string(p[:n])
	
	return user, passwd, err
}

// Authentication answer, b Answer code.
// Method: AuthNone or AuthUser
// Status: ReplyPass or ReplyFail
func (s *Socks5) AuthRepies(b byte) error {
	_, err := s.w.Write([]byte{VER, b})
	if err != nil {
		return err
	}
	err = s.w.Flush()
	return err
}

// Send authentication method
func (s *Socks5) AuthSendMethods(method byte) error {
	rep := []byte{VER, 0x01, method}
	_, err := s.w.Write(rep)
	if err != nil {
		return err
	}
	return s.w.Flush()
}

// Send the authentication user/password
func (s *Socks5) AuthSendUser(name, passwd string) error {
	rep := []byte{VER}
	rep = append(rep, uint8(len(name)))
	rep = append(rep, []byte(name)...)
	rep = append(rep, uint8(len(passwd)))
	rep = append(rep, []byte(passwd)...)
	_, err := s.w.Write(rep)
	if err != nil {
		return err
	}
	return s.w.Flush()
}

// Connect to a server, return net.Conn, error
func (s *Socks5) Dial(host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	server, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%d - %w", host, port, err)
	}
	return server, nil
}

// Forward
func (s *Socks5) Forward(server, client net.Conn) {
	defer func() {
		server.Close()
		client.Close()
	}()

	go io.Copy(server, client)
	io.Copy(client, server)
}

// Get the version number, not 5 returns an error
func (s *Socks5) GetVer() error {
	ver, err := s.r.ReadByte()
	if err != nil {
		return err
	}
	if ver != VER {
		return ErrVer
	}
	return nil
}

// Resolve host from Requests
func (s *Socks5) ParsetHost(atyp byte) (string, error) {
	host := ""
	var err error
	switch atyp {
	case DomainName: // DomainName
		dlen, err := s.r.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, int(dlen))
		_, err = s.r.Read(buf)
		if err != nil {
			return "", err
		}
		host = string(buf)
	case IPv4, IPv6: // IPv4 or IPv6
		var buf []byte
		if atyp == IPv4 {
			buf = make([]byte, net.IPv4len)
		} else {
			buf = make([]byte, net.IPv6len)
		}
		_, err = s.r.Read(buf)
		if err != nil {
			return "", err
		}
		if atyp == IPv4 {
			host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		} else {
			host = fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7])
		}
	default:
		err = errors.New("unknown address type")
	}
	return string(host), err
}

// Resolve port from Requests
func (s *Socks5) ParsePort() (int, error) {
	p := make([]byte, 2)
	_, err := s.r.Read(p)
	if err != nil {
		return 0, err
	}
	port := binary.BigEndian.Uint16(p)
	return int(port), nil
}

// Respond to the client
func (s *Socks5) Replies(rep byte, atyp byte, addr net.Addr) error {
	buf := []byte{VER, rep, 0x00, atyp}
	if addr == nil {
		buf = append(buf, 0, 0, 0, 0, 0, 0)
	} else {
		addr := addr.(*net.TCPAddr)
		switch atyp {
		case IPv4:
			ip := addr.IP.To4()
			buf = append(buf, ip...)
		case DomainName:
			host := addr.String()
			buf = append(buf, uint8(len(host)))
			buf = append(buf, []byte(host)...)
		case IPv6:
			ip := addr.IP.To16()
			buf = append(buf, ip...)
		}

		port := make([]byte, 2)
		port[1] = uint8(addr.Port)
		port[0] = uint8(addr.Port >> 8)
		buf = append(buf, port...)
	}

	_, err := s.w.Write(buf)
	if err != nil {
		return err
	}
	err = s.w.Flush()
	return err
}

// Get the request data
func (s *Socks5) Requests() (host string, port int, atyp byte, err error) {
	err = s.GetVer()
	if err != nil {
		return host, port, atyp, err
	}

	cmd, err := s.r.ReadByte()
	if err != nil {
		return host, port, atyp, err
	}
	if cmd != CONNECT {
		return "", 0, 0, ErrConnect
	}

	p := make([]byte, 2)
	_, err = s.r.Read(p)
	if err != nil {
		return host, port, atyp, err
	}
	atyp = p[1]
	host, err = s.ParsetHost(atyp)
	if err != nil {
		return host, port, atyp, err
	}

	port, err = s.ParsePort()
	if err != nil {
		return host, port, atyp, err
	}
	return host, port, atyp, nil
}
