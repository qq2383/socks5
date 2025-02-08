package socket5

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Socket version number
var (
	VER byte = 0x05
)

// The values currently defined for METHOD are:
// AuthNone: NO AUTHENTICATION REQUIRED
// AuthUser: USERNAME/PASSWORD
// ReplyPass: The identity authentication is passed
// ReplyFail: Authentication failed
var (
	AuthNone  byte = 0x00
	AuthUser  byte = 0x02
	ReplyPass byte = 0x00
	ReplyFail byte = 0x01
)

// Request atyp value 
var (
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

// Socket5 struct 
type Socket5 struct {
	r *bufio.Reader
	w *bufio.Writer
}

// New Socket5 func 
func New(conn net.Conn) *Socket5 {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	return &Socket5{r: r, w: w}
}

// Obtain the authentication method, return methods 
func (s *Socket5) AuthGetMethods() ([]byte, error) {
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

// Send authentication method 
func (s *Socket5) AuthSendMethods(method byte) error {
	rep := []byte{VER, 0x01, method}
	_, err := s.w.Write(rep)
	if err != nil {
		return err
	}
	return s.w.Flush()
}

// How to obtain the authentication 
func (s *Socket5) AuthGetMethod() (byte, error) {
	err := s.GetVer()
	if err != nil {
		return 0, err
	}

	return s.r.ReadByte()
}

// Send the authentication user/password 
func (s *Socket5) AuthSendUser(name, passwd string) error {
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

// Obtain an authenticated user, return user name and passwd 
func (s *Socket5) AuthGetUser() (user, passwd string, err error) {
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
	fmt.Println(user)

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
	fmt.Println(passwd)
	return user, passwd, err
}

// Obtain the authentication status
// If the error parameter is set to nil, the authentication is passed
// otherwise the authentication fails
func (s *Socket5) AuthGetStatus() error {
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

// Authentication answer, b Answer code,
// Method: AuthNone or AuthUser
// Status: ReplyPass or ReplyFail 
func (s *Socket5) AuthRepies(b byte) error {
	_, err := s.w.Write([]byte{VER, b})
	if err != nil {
		return err
	}
	err = s.w.Flush()
	return err
}

// Connect to a server, return net.Conn, error
func (s *Socket5) Dial(host string, port int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	server, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%d - %w", host, port, err)
	}
	return server, nil
}

// Get the version number, not 5 returns an error 
func (s *Socket5) GetVer() error {
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
func (s *Socket5) ParsetHost(atyp byte) (string, error) {
	var host []byte
	var err error
	switch atyp {
	case DomainName: // DomainName
		dlen, err := s.r.ReadByte()
		if err != nil {
			return "", err
		}
		p := make([]byte, int(dlen))
		_, err = s.r.Read(p)
		if err != nil {
			return "", err
		}
		host = p
	case IPv4, IPv6: // IPv6
		var ip net.IP
		_, err = s.r.Read(ip)
		if err != nil {
			return "", err
		}
		if atyp == IPv4 {
			host = net.IP(ip).To4()
		} else {
			host = net.IP(ip)
		}
	default:
		err = errors.New("unknown address type")
	}
	return string(host), err
}

// Resolve port from Requests
func (s *Socket5) ParsePort() (int, error) {
	p := make([]byte, 2)
	_, err := s.r.Read(p)
	if err != nil {
		return 0, err
	}
	port := binary.BigEndian.Uint16(p)
	return int(port), nil
}

// Get the request data 
func (s *Socket5) Requests() (host string, port int, atyp byte, err error) {
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

// Respond to the client 
func (s *Socket5) Replies(rep byte, atyp byte, addr net.Addr) error {
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

// Forward 
func (s *Socket5) Forward(server, client net.Conn) {
	defer func() {
		server.Close()
		client.Close()
	}()

	go io.Copy(server, client)
	io.Copy(client, server)
}
