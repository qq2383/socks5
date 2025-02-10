# Overview

A socket5-based package

# Index 
[Constants](#constants)  
[Variables](#variables)  
[type Socks5](#type-socks5)  
>[func New(conn net.Conn) *Socks5](#func-new)  
>[func (s *Socks5) AuthGetMethod() (byte, error)](#func-s-socks5-authgetmethod)  
>[func (s *Socks5) AuthGetMethods() ([]byte, error)) *Socks5](#func-s-socks5-authgetmethods)  
>[func (s *Socks5) AuthGetStatus() error](#func-s-socks5-authgetstatus)  
>[func (s *Socks5) AuthGetUser() (user, passwd string, err error)](#func-s-socks5-authgetuser)  
>[func (s *Socks5) AuthRepies(b byte) error](#func-s-socks5-authrepies)  
>[func (s *Socks5) AuthSendMethods(method byte) error](#func-s-socks5-authsendmethods)  
>[func (s *Socks5) AuthSendUser(name, passwd string) error](#func-s-socks5-authsenduser)  
>[func (s *Socks5) Dial(host string, port int) (net.Conn, error)](#func-s-socks5-dial)  
>[func (s *Socks5) Forward(server, client net.Conn) ](#func-s-socks5-forward)  
>[func (s *Socks5) GetVer() error](#func-s-socks5-getver)  
>[func (s *Socks5) ParsePort() (int, error)](#func-s-socks5-parseport)  
>[func (s *Socks5) ParsetHost(atyp byte) (string, error)](#func-s-socks5-parsethost)  
>[func (s *Socks5) Replies(rep byte, atyp byte, addr net.Addr) error ](#func-s-socks5-replies)  
>[func (s *Socks5) Requests() (host string, port int, atyp byte, err error)](#func-s-socks5-requests)  

# Constants
```
const (
	VER byte = 0x05
)
```
Socket version number

```
const (
	AuthNone  byte = 0x00
	AuthUser  byte = 0x02
	ReplyPass byte = 0x00
	ReplyFail byte = 0x01
)
```
The values currently defined for METHOD are:  
AuthNone: NO AUTHENTICATION REQUIRED  
AuthUser: USERNAME/PASSWORD  
ReplyPass: The identity authentication is passed  
ReplyFail: Authentication failed

```
const (
	BIND          byte = 0x02
	CONNECT       byte = 0x01
	DomainName    byte = 0x03
	IPv4          byte = 0x01
	IPv6          byte = 0x04
	UDP_ASSOCIATE byte = 0x03
)
```
Request atyp value

# Variables 
```
var (
	ErrVer      = errors.New("version not 5")
	ErrConnect  = errors.New("this server only support cmd is 0x01")
	ErrAuthFail = fmt.Errorf("authentication failed")
)
```
The error code are:  
ErrVer: Version not 5  
ErrConnect: Methods only support connect  
ErrAuthFail: The username or password is incorrectly authenticated

# Types 
## type Socks5
```
type Socks5 struct {
	r *bufio.Reader
	w *bufio.Writer
}
```
Socks5 struct 

## func New
```
func New(conn net.Conn) *Socks5
```
New Socks5 function

## func (s *Socks5) AuthGetMethod
```
func (s *Socks5) AuthGetMethod() (byte, error)
```
How to obtain the authentication 

## func (s *Socks5) AuthGetMethods
```
func (s *Socks5) AuthGetMethods() ([]byte, error)
```
Obtain the authentication method, return methods

## func (s *Socks5) AuthGetStatus
```
func (s *Socks5) AuthGetStatus() error
```
Obtain the authentication status,
If the error parameter is set to nil, the authentication is passed,
otherwise the authentication fails

## func (s *Socks5) AuthGetUser
```
func (s *Socks5) AuthGetUser() (user, passwd string, err error)
```
Obtain an authenticated user, return user name and passwd 

## func (s *Socks5) AuthRepies
```
func (s *Socks5) AuthRepies(b byte) error
```
Authentication answer, b Answer code.  
Method: AuthNone or AuthUser  
Status: ReplyPass or ReplyFail 

## func (s *Socks5) AuthSendMethods
```
func (s *Socks5) AuthSendMethods(method byte) error
```
Send authentication method 

## func (s *Socks5) AuthSendUser
```
func (s *Socks5) AuthSendUser(name, passwd string) error
```
Send the authentication user/password

## func (s *Socks5) Dial
```
func (s *Socks5) Dial(host string, port int) (net.Conn, error)
```
Connect to a server, return net.Conn, error

## func (s *Socks5) Forward
```
func (s *Socks5) Forward(server, client net.Conn) 
```
Forward 

## func (s *Socks5) GetVer
```
func (s *Socks5) GetVer() error
```
Get the version number, not 5 returns an error

## func (s *Socks5) ParsePort
```
func (s *Socks5) ParsePort() (int, error)
```
Resolve port from Requests

## func (s *Socks5) ParsetHost
```
func (s *Socks5) ParsetHost(atyp byte) (string, error)
```
Resolve host from Requests

## func (s *Socks5) Replies
```
func (s *Socks5) Replies(rep byte, atyp byte, addr net.Addr) error 
```
Respond to the client 

## func (s *Socks5) Requests
```
func (s *Socks5) Requests() (host string, port int, atyp byte, err error)
```
Get the request data 


