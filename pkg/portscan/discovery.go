package portscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zan8in/afrog/v3/pkg/progress"
	"github.com/zan8in/gologger"
	"golang.org/x/net/icmp"
)

type phaseProgress struct {
	opt         *Options
	phase       string
	total       uint64
	start       time.Time
	done        uint64
	alive       uint64
	lastPercent int32
	stop        chan struct{}
	printMu     sync.Mutex
}

func newPhaseProgress(opt *Options, phase string, total int) *phaseProgress {
	if total < 0 {
		total = 0
	}
	return &phaseProgress{
		opt:         opt,
		phase:       phase,
		total:       uint64(total),
		lastPercent: -1,
		stop:        make(chan struct{}),
	}
}

func (p *phaseProgress) enabled() bool {
	return p != nil && p.opt != nil && p.total > 0 && (p.opt.OnProgress != nil || (!p.opt.Quiet && p.opt.Debug))
}

func (p *phaseProgress) startRender(ctx context.Context) {
	if !p.enabled() {
		return
	}
	p.start = time.Now()
	p.render(false)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.stop:
				return
			case <-ticker.C:
				p.render(false)
			}
		}
	}()
}

func (p *phaseProgress) stopRender() {
	if p == nil {
		return
	}
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	p.render(true)
	if p.opt != nil && !p.opt.Quiet && p.opt.Debug && p.total > 0 {
		fmt.Fprint(os.Stderr, "\r\033[2K\r")
	}
}

func (p *phaseProgress) attempt() {
	if p == nil {
		return
	}
	atomic.AddUint64(&p.done, 1)
}

func (p *phaseProgress) markAlive(host, proto string) {
	if p == nil || p.opt == nil {
		return
	}
	atomic.AddUint64(&p.alive, 1)
	if p.opt.OnDiscoveredHost != nil && strings.TrimSpace(host) != "" {
		p.opt.OnDiscoveredHost(host)
	}
	if p.opt.LogDiscoveredHosts || p.opt.Debug {
		if p.opt.Debug && !p.opt.Quiet {
			fmt.Fprint(os.Stderr, "\r\033[2K\r")
		}
		gologger.Print().Msg(host)
	}
}

func (p *phaseProgress) render(final bool) {
	if p == nil || p.opt == nil {
		return
	}
	p.printMu.Lock()
	defer p.printMu.Unlock()

	done := atomic.LoadUint64(&p.done)
	total := p.total
	if total == 0 {
		return
	}
	if done > total {
		done = total
	}
	percent := int(done * 100 / total)
	if final {
		percent = 100
	}
	if p.opt.OnProgress != nil {
		status := "running"
		if final {
			status = "completed"
		}
		p.opt.OnProgress("host_discovery", status, int(done), int(total), percent)
	}
	printEnabled := !p.opt.Quiet && p.opt.Debug && total > 0
	if !printEnabled {
		return
	}
	if !final && int32(percent) == atomic.LoadInt32(&p.lastPercent) {
		return
	}
	atomic.StoreInt32(&p.lastPercent, int32(percent))

	elapsed := strings.Split(time.Since(p.start).String(), ".")[0] + "s"
	suffix := ""
	fmt.Fprint(os.Stderr, "\r\033[2K")
	fmt.Fprintf(os.Stderr, "\r[%s] %d%% (%d/%d), %s%s", progress.GetProgressBar(percent, 0), percent, done, total, elapsed, suffix)
}

func DiscoverAliveHosts(ctx context.Context, opt *Options, hosts []string) ([]string, error) {
	if opt.SkipDiscovery || len(hosts) <= 1 {
		return hosts, nil
	}
	method := strings.ToLower(strings.TrimSpace(opt.DiscoveryMethod))
	if method == "" || method == "auto" {
		var alive []string
		var err error
		pending := hosts
		conn, e := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if e == nil {
			defer conn.Close()
			pp := newPhaseProgress(opt, "icmp", len(pending))
			pp.startRender(ctx)
			alive, err = runICMPListen(ctx, pending, conn, opt, pp)
			pp.stopRender()
			if err == nil && len(alive) > 0 && len(alive) < len(pending) {
				pending = diffHosts(pending, alive)
			}
		}
		if len(pending) > 0 {
			c2, e2 := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
			if e2 == nil {
				c2.Close()
				pp := newPhaseProgress(opt, "icmp", len(pending))
				pp.startRender(ctx)
				add2, _ := runICMPNoListen(ctx, pending, opt, pp)
				pp.stopRender()
				alive = mergeUnique(alive, add2)
				pending = diffHosts(pending, add2)
			}
		}
		if len(pending) > 0 {
			pp := newPhaseProgress(opt, "ping", len(pending))
			pp.startRender(ctx)
			add3 := runPing(ctx, pending, opt, pp)
			pp.stopRender()
			alive = mergeUnique(alive, add3)
			pending = diffHosts(pending, add3)
		}
		if len(pending) > 0 && opt.DiscoveryRetries > 0 {
			for i := 0; i < opt.DiscoveryRetries && len(pending) > 0; i++ {
				pp := newPhaseProgress(opt, "ping", len(pending))
				pp.startRender(ctx)
				addp := runPing(ctx, pending, opt, pp)
				pp.stopRender()
				alive = mergeUnique(alive, addp)
				pending = diffHosts(pending, addp)
			}
		}
		if len(pending) > 0 {
			pp := newPhaseProgress(opt, "tcp", len(pending))
			pp.startRender(ctx)
			add4 := runTCPDiscovery(ctx, opt, pending, pp)
			pp.stopRender()
			alive = mergeUnique(alive, add4)
		}
		logAliveStats(alive, opt)
		return alive, nil
	}
	if method == "icmp" {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err == nil {
			defer conn.Close()
			pp := newPhaseProgress(opt, "icmp", len(hosts))
			pp.startRender(ctx)
			alive, _ := runICMPListen(ctx, hosts, conn, opt, pp)
			pp.stopRender()
			logAliveStats(alive, opt)
			return alive, nil
		}
		pp := newPhaseProgress(opt, "icmp", len(hosts))
		pp.startRender(ctx)
		alive, _ := runICMPNoListen(ctx, hosts, opt, pp)
		pp.stopRender()
		logAliveStats(alive, opt)
		return alive, nil
	}
	if method == "ping" {
		pp := newPhaseProgress(opt, "ping", len(hosts))
		pp.startRender(ctx)
		res := runPing(ctx, hosts, opt, pp)
		pp.stopRender()
		logAliveStats(res, opt)
		return res, nil
	}
	pp := newPhaseProgress(opt, "tcp", len(hosts))
	pp.startRender(ctx)
	res := runTCPDiscovery(ctx, opt, hosts, pp)
	pp.stopRender()
	logAliveStats(res, opt)
	return res, nil
}

func runICMPListen(ctx context.Context, hosts []string, conn *icmp.PacketConn, opt *Options, pp *phaseProgress) ([]string, error) {
	var alive []string
	seen := make(map[string]struct{})
	var mu sync.Mutex
	endflag := false
	go func() {
		select {
		case <-ctx.Done():
			endflag = true
		}
	}()
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
				if pp != nil {
					pp.markAlive(ip, "icmp-listen")
				} else {
					logHostAlive(ip, "icmp-listen", opt)
				}
				alive = append(alive, ip)
			}
			mu.Unlock()
		}
	}()
	for _, h := range shuffled {
		if ctx.Err() != nil || endflag {
			break
		}
		if pp != nil {
			pp.attempt()
		}
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
		if time.Since(start) > wait || ctx.Err() != nil || endflag {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	endflag = true
	return alive, nil
}

func runICMPNoListen(ctx context.Context, hosts []string, opt *Options, pp *phaseProgress) ([]string, error) {
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
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()
			if pp != nil {
				pp.attempt()
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			if icmpAlive(host) {
				mu.Lock()
				if pp != nil {
					pp.markAlive(host, "icmp")
				} else {
					logHostAlive(host, "icmp", opt)
				}
				alive = append(alive, host)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	close(limiter)
	return alive, nil
}

func runPing(ctx context.Context, hosts []string, opt *Options, pp *phaseProgress) []string {
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	limit := opt.PingConcurrency
	if limit <= 0 {
		limit = 50
	}
	limiter := make(chan struct{}, limit)
	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()
			if pp != nil {
				pp.attempt()
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			if execPing(host) {
				mu.Lock()
				if pp != nil {
					pp.markAlive(host, "ping")
				} else {
					logHostAlive(host, "ping", opt)
				}
				alive = append(alive, host)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return alive
}

func runTCPDiscovery(ctx context.Context, opt *Options, hosts []string, pp *phaseProgress) []string {
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	primary := opt.DiscoveryPorts
	if len(primary) == 0 {
		primary = []int{443, 80, 22, 3389, 445, 135, 8080, 8443}
	}
	fallback := opt.DiscoveryFallbackPorts
	if len(fallback) == 0 {
		fallback = []int{81, 21, 25, 139, 8081, 8888, 9090, 9443, 8000, 9000, 3128}
	}
	limit := opt.RateLimit
	if limit < 100 {
		limit = 100
	}
	sem := make(chan struct{}, limit)
	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			if pp != nil {
				pp.attempt()
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			ok := false
			for _, p := range primary {
				c, e := net.DialTimeout("tcp", net.JoinHostPort(h, strconv.Itoa(p)), opt.Timeout)
				if e == nil {
					c.Close()
					ok = true
					break
				}
				if isConnRefused(e) {
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
					if isConnRefused(e) {
						ok = true
						break
					}
				}
			}
			if ok {
				mu.Lock()
				if pp != nil {
					pp.markAlive(h, "tcp")
				} else {
					logHostAlive(h, "tcp", opt)
				}
				alive = append(alive, h)
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	return alive
}

func isConnRefused(err error) bool {
	if err == nil {
		return false
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return true
		}
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, syscall.ECONNREFUSED) {
				return true
			}
		}
	}

	return strings.Contains(strings.ToLower(err.Error()), "refused")
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
	if opt == nil || opt.Quiet || !opt.Debug {
		return
	}
	top := opt.DiscoveryTop
	if top <= 0 {
		top = 10
	}
	if len(alive) > 1000 {
		at, al := countTop(alive, top, true)
		for i := 0; i < len(at); i++ {
			gologger.Debug().Msgf("Alive /16: %s => %d", at[i], al[i])
		}
	}
	if len(alive) > 256 {
		at, al := countTop(alive, top, false)
		for i := 0; i < len(at); i++ {
			gologger.Debug().Msgf("Alive /24: %s => %d", at[i], al[i])
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
		gologger.Print().Msg(host)
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
