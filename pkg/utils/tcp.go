package utils

import (
	"net"
	"time"
)

func Tcp(addr string, data []byte) ([]byte, error) {
	timeout := time.Duration(6) * time.Second
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 20480)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}
