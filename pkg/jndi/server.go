package jndi

import (
	"net"
	"time"
)

var JndiAddress string

type Server struct {
	TcpListen *net.TCPListener
}

type Conn struct {
	TcpConn *net.TCPConn
}

func (s *Server) Accept() *Conn {
	server, _ := s.TcpListen.AcceptTCP()
	return &Conn{TcpConn: server}
}

func (s *Server) Bind(addr net.TCPAddr) error {
	tcp, err := net.ListenTCP("tcp", &addr)
	if err != nil {
		return err
	}
	s.TcpListen = tcp
	return nil
}

func (s *Server) Close() {
	s.TcpListen.Close()
}

func (s *Server) GetInetAddress() net.Addr {
	return s.TcpListen.Addr()
}

func (s *Server) SetSoTimeout(timeout int) {
	duration := time.Duration(timeout)
	s.TcpListen.SetDeadline(time.Now().Add(duration * time.Millisecond))
}
