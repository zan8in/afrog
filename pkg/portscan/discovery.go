package portscan

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/proxy"
)

func DiscoverAliveHosts(ctx context.Context, opt *Options, hosts []string) ([]string, error) {
	if opt.SkipDiscovery || len(hosts) <= 1 {
		return hosts, nil
	}
	method := strings.ToLower(strings.TrimSpace(opt.DiscoveryMethod))
	if method == "" || method == "auto" {
		var alive []string
		var err error
		pending := hosts
		var d proxy.Dialer
		if opt.Proxy != "" {
			u, perr := url.Parse(opt.Proxy)
			if perr == nil {
				if u.Scheme == "http" {
					d = NewHttpProxyDialer(u)
				} else {
					d, _ = proxy.FromURL(u, proxy.Direct)
				}
			}
		}
		conn, e := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if e == nil {
			defer conn.Close()
			alive, err = runICMPListen(ctx, pending, conn, opt)
			if err == nil && len(alive) > 0 && len(alive) < len(pending) {
				pending = diffHosts(pending, alive)
			}
		}
		if len(pending) > 0 {
			c2, e2 := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
			if e2 == nil {
				c2.Close()
				add2, _ := runICMPNoListen(ctx, pending, opt)
				alive = mergeUnique(alive, add2)
				pending = diffHosts(pending, add2)
			}
		}
		if len(pending) > 0 {
			add3 := runPing(ctx, pending, opt)
			alive = mergeUnique(alive, add3)
			pending = diffHosts(pending, add3)
		}
		if len(pending) > 0 && opt.DiscoveryRetries > 0 {
			for i := 0; i < opt.DiscoveryRetries && len(pending) > 0; i++ {
				addp := runPing(ctx, pending, opt)
				alive = mergeUnique(alive, addp)
				pending = diffHosts(pending, addp)
			}
		}
		if len(pending) > 0 {
			add4 := runTCPDiscoveryWithDialer(ctx, opt, pending, d)
			alive = mergeUnique(alive, add4)
		}
		logAliveStats(alive, opt)
		return alive, nil
	}
	if method == "icmp" {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err == nil {
			defer conn.Close()
			alive, _ := runICMPListen(ctx, hosts, conn, opt)
			logAliveStats(alive, opt)
			return alive, nil
		}
		alive, _ := runICMPNoListen(ctx, hosts, opt)
		logAliveStats(alive, opt)
		return alive, nil
	}
	if method == "ping" {
		res := runPing(ctx, hosts, opt)
		logAliveStats(res, opt)
		return res, nil
	}
	res := runTCPDiscovery(ctx, opt, hosts)
	logAliveStats(res, opt)
	return res, nil
}

func runICMPListen(ctx context.Context, hosts []string, conn *icmp.PacketConn, opt *Options) ([]string, error) {
	var alive []string
	seen := make(map[string]struct{})
	var mu sync.Mutex
	endflag := false
	shuffled := append([]string(nil), hosts...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	go func() {
		buf := make([]byte, 128)
		for {
			if endflag {
				return
			}
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, src, err := conn.ReadFrom(buf)
			if err != nil || src == nil {
				continue
			}
			ip := src.String()
			mu.Lock()
			if _, ok := seen[ip]; !ok && containsHost(hosts, ip) {
				seen[ip] = struct{}{}
				logHostAlive(ip, "icmp-listen", opt)
				alive = append(alive, ip)
			}
			mu.Unlock()
		}
	}()
	for _, h := range shuffled {
		dst, _ := net.ResolveIPAddr("ip", h)
		msg := makeICMPEcho(h)
		conn.WriteTo(msg, dst)
	}
	start := time.Now()
	for {
		if len(alive) == len(hosts) {
			break
		}
		wait := 6 * time.Second
		if len(hosts) <= 256 {
			wait = 3 * time.Second
		}
		if time.Since(start) > wait {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	endflag = true
	logAliveStats(alive, opt)
	return alive, nil
}

func runICMPNoListen(ctx context.Context, hosts []string, opt *Options) ([]string, error) {
	num := opt.IcmpConcurrency
	if num <= 0 {
		num = 1000
	}
	if len(hosts) < num {
		num = len(hosts)
	}
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	for _, h := range hosts {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()
			if icmpAlive(host) {
				mu.Lock()
				logHostAlive(host, "icmp", opt)
				alive = append(alive, host)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	close(limiter)
	logAliveStats(alive, opt)
	return alive, nil
}

func runPing(ctx context.Context, hosts []string, opt *Options) []string {
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	limit := opt.PingConcurrency
	if limit <= 0 {
		limit = 50
	}
	limiter := make(chan struct{}, limit)
	for _, h := range hosts {
		select {
		case <-ctx.Done():
			break
		default:
		}
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()
			if execPing(host) {
				mu.Lock()
				logHostAlive(host, "ping", opt)
				alive = append(alive, host)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	logAliveStats(alive, opt)
	return alive
}

func runTCPDiscovery(ctx context.Context, opt *Options, hosts []string) []string {
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	primary := opt.DiscoveryPorts
	if len(primary) == 0 {
		primary = []int{443, 80, 22, 3389}
	}
	fallback := opt.DiscoveryFallbackPorts
	if len(fallback) == 0 {
		fallback = []int{21, 25, 502, 102, 123, 135, 445}
	}
	limit := opt.RateLimit
	if limit < 100 {
		limit = 100
	}
	sem := make(chan struct{}, limit)
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			ok := false
			for _, p := range primary {
				c, e := net.DialTimeout("tcp", net.JoinHostPort(h, strconv.Itoa(p)), opt.Timeout)
				if e == nil {
					c.Close()
					ok = true
					break
				}
			}
			if !ok && opt.DiscoveryFallback {
				for _, p := range fallback {
					c, e := net.DialTimeout("tcp", net.JoinHostPort(h, strconv.Itoa(p)), opt.Timeout)
					if e == nil {
						c.Close()
						ok = true
						break
					}
				}
			}
			if ok {
				mu.Lock()
				logHostAlive(h, "tcp", opt)
				alive = append(alive, h)
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	logAliveStats(alive, opt)
	return alive
}

func runTCPDiscoveryWithDialer(ctx context.Context, opt *Options, hosts []string, d proxy.Dialer) []string {
	if d == nil {
		return runTCPDiscovery(ctx, opt, hosts)
	}
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	primary := opt.DiscoveryPorts
	if len(primary) == 0 {
		primary = []int{443, 80, 22, 3389}
	}
	fallback := opt.DiscoveryFallbackPorts
	if len(fallback) == 0 {
		fallback = []int{21, 25, 502, 102, 123, 135, 445}
	}
	limit := opt.RateLimit
	if limit < 100 {
		limit = 100
	}
	sem := make(chan struct{}, limit)
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			ok := false
			for _, p := range primary {
				if tcpOpenViaDialer(ctx, d, h, p, opt.Timeout) {
					ok = true
					break
				}
			}
			if !ok && opt.DiscoveryFallback {
				for _, p := range fallback {
					if tcpOpenViaDialer(ctx, d, h, p, opt.Timeout) {
						ok = true
						break
					}
				}
			}
			if ok {
				mu.Lock()
				logHostAlive(h, "tcp", opt)
				alive = append(alive, h)
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	logAliveStats(alive, opt)
	return alive
}

func tcpOpenViaDialer(ctx context.Context, d proxy.Dialer, host string, port int, to time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	type res struct {
		c net.Conn
		e error
	}
	ch := make(chan res, 1)
	go func() {
		c, e := d.Dial("tcp", addr)
		ch <- res{c, e}
	}()
	select {
	case r := <-ch:
		if r.e == nil {
			r.c.Close()
			return true
		}
		return false
	case <-time.After(to):
		return false
	}
}

func icmpAlive(host string) bool {
	start := time.Now()
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(start.Add(6 * time.Second))
	msg := makeICMPEcho(host)
	_, err = conn.Write(msg)
	if err != nil {
		return false
	}
	recv := make([]byte, 64)
	_, err = conn.Read(recv)
	if err != nil {
		return false
	}
	return true
}

func logAliveStats(alive []string, opt *Options) {
	top := opt.DiscoveryTop
	if top <= 0 {
		top = 10
	}
	if len(alive) > 1000 {
		at, al := countTop(alive, top, true)
		for i := 0; i < len(at); i++ {
			fmt.Fprintf(os.Stderr, "Alive /16: %s => %d\n", at[i], al[i])
		}
	}
	if len(alive) > 256 {
		at, al := countTop(alive, top, false)
		for i := 0; i < len(at); i++ {
			fmt.Fprintf(os.Stderr, "Alive /24: %s => %d\n", at[i], al[i])
		}
	}
}

func countTop(list []string, top int, bSegment bool) (keys []string, vals []int) {
	m := make(map[string]int)
	for _, ip := range list {
		parts := strings.Split(ip, ".")
		if len(parts) != 4 {
			continue
		}
		var key string
		if bSegment {
			key = parts[0] + "." + parts[1]
		} else {
			key = parts[0] + "." + parts[1] + "." + parts[2]
		}
		m[key]++
	}
	for i := 0; i < top && len(m) > 0; i++ {
		mk := ""
		mv := 0
		for k, v := range m {
			if v > mv {
				mv = v
				mk = k
			}
		}
		if mk == "" {
			break
		}
		keys = append(keys, mk)
		vals = append(vals, mv)
		delete(m, mk)
	}
	return
}
func logHostAlive(host, proto string, opt *Options) {
	if opt.LogDiscoveredHosts || opt.Debug {
		fmt.Fprintf(os.Stderr, "Alive Host: %s [%s]\n", host, proto)
	}
}
func execPing(ip string) bool {
	for _, c := range []string{";", "&", "|", "`", "$", "\\", "'", "%", "\"", "\n"} {
		if strings.Contains(ip, c) {
			return false
		}
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
	case "darwin":
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false")
	default:
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false")
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return false
	}
	if err := cmd.Wait(); err != nil {
		return false
	}
	s := out.String()
	return strings.Contains(s, "true")
}

func makeICMPEcho(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := ident(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = seq(1)
	chk := csum(msg[0:40])
	msg[2] = byte(chk >> 8)
	msg[3] = byte(chk & 255)
	return msg
}

func csum(b []byte) uint16 {
	s := 0
	n := len(b)
	for i := 0; i < n-1; i += 2 {
		s += int(b[i])*256 + int(b[i+1])
	}
	if n%2 == 1 {
		s += int(b[n-1]) * 256
	}
	s = (s >> 16) + (s & 0xffff)
	s = s + (s >> 16)
	return uint16(^s)
}

func seq(v int16) (byte, byte) {
	return byte(v >> 8), byte(v & 255)
}

func ident(host string) (byte, byte) {
	if len(host) >= 2 {
		return host[0], host[1]
	}
	if len(host) == 1 {
		return host[0], 0
	}
	return 0, 0
}

func containsHost(list []string, h string) bool {
	for _, v := range list {
		if v == h {
			return true
		}
	}
	return false
}

func mergeUnique(a, b []string) []string {
	m := make(map[string]struct{})
	for _, v := range a {
		m[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := m[v]; !ok {
			a = append(a, v)
			m[v] = struct{}{}
		}
	}
	return a
}

func diffHosts(all, found []string) []string {
	m := make(map[string]struct{})
	for _, v := range found {
		m[v] = struct{}{}
	}
	var res []string
	for _, v := range all {
		if _, ok := m[v]; !ok {
			res = append(res, v)
		}
	}
	return res
}
