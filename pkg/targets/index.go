package targets

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

type TargetIndex struct {
	URLs              []string
	Hosts             []string
	HostPorts         []string
	Expandable        []string
	AllCanonicalKeys  []string
	canonicalKeyIndex map[string]struct{}
}

func NewTargetIndex() *TargetIndex {
	return &TargetIndex{
		canonicalKeyIndex: make(map[string]struct{}),
	}
}

func BuildTargetIndex(seeds []string) *TargetIndex {
	idx := NewTargetIndex()
	idx.AddAll(seeds)
	return idx
}

func (idx *TargetIndex) AddAll(seeds []string) {
	for _, s := range seeds {
		idx.Add(s)
	}
}

func (idx *TargetIndex) Add(seed string) bool {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return false
	}

	if norm, key, ok := normalizeExpandable(seed); ok {
		if idx.addKey(key) {
			idx.Expandable = append(idx.Expandable, norm)
			return true
		}
		return false
	}

	if norm, key, ok := normalizeURL(seed); ok {
		if idx.addKey(key) {
			idx.URLs = append(idx.URLs, norm)
			return true
		}
		return false
	}

	if norm, key, ok := normalizeHostPort(seed); ok {
		if idx.addKey(key) {
			idx.HostPorts = append(idx.HostPorts, norm)
			return true
		}
		return false
	}

	if norm, key, ok := normalizeHost(seed); ok {
		if idx.addKey(key) {
			idx.Hosts = append(idx.Hosts, norm)
			return true
		}
		return false
	}

	return false
}

func (idx *TargetIndex) addKey(key string) bool {
	if _, ok := idx.canonicalKeyIndex[key]; ok {
		return false
	}
	idx.canonicalKeyIndex[key] = struct{}{}
	idx.AllCanonicalKeys = append(idx.AllCanonicalKeys, key)
	return true
}

func (idx *TargetIndex) PreScanTargets() []string {
	seen := make(map[string]struct{}, len(idx.Hosts)+len(idx.Expandable)+len(idx.URLs)+len(idx.HostPorts))
	out := make([]string, 0, len(seen))

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	for _, e := range idx.Expandable {
		add(e)
	}
	for _, h := range idx.Hosts {
		add(h)
	}
	for _, hp := range idx.HostPorts {
		host, _, err := net.SplitHostPort(strings.TrimSpace(hp))
		if err != nil {
			continue
		}
		add(host)
	}
	for _, rawURL := range idx.URLs {
		u, err := url.Parse(strings.TrimSpace(rawURL))
		if err != nil || u == nil {
			continue
		}
		if u.Hostname() == "" {
			continue
		}
		add(normalizeHostValue(u.Hostname()))
	}

	return out
}

func (idx *TargetIndex) NetTargets() []string {
	seen := make(map[string]struct{}, len(idx.Hosts)+len(idx.URLs)+len(idx.HostPorts))
	out := make([]string, 0, len(seen))

	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	for _, h := range idx.Hosts {
		add(h)
	}
	for _, hp := range idx.HostPorts {
		add(hp)
	}
	for _, rawURL := range idx.URLs {
		u, err := url.Parse(strings.TrimSpace(rawURL))
		if err != nil || u == nil {
			continue
		}
		if u.Hostname() == "" {
			continue
		}
		add(normalizeHostValue(u.Hostname()))
	}

	return out
}

func normalizeExpandable(seed string) (normalized string, canonicalKey string, ok bool) {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return "", "", false
	}

	if _, ipnet, err := net.ParseCIDR(seed); err == nil && ipnet != nil {
		n := ipnet.String()
		return n, "expand:" + n, true
	}

	if strings.Contains(seed, "-") {
		parts := strings.Split(seed, "-")
		if len(parts) != 2 {
			return "", "", false
		}
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start == nil || end == nil {
			return "", "", false
		}
		n := start.String() + "-" + end.String()
		return n, "expand:" + n, true
	}

	return "", "", false
}

func normalizeURL(seed string) (normalized string, canonicalKey string, ok bool) {
	s := strings.TrimSpace(seed)
	if s == "" {
		return "", "", false
	}

	inferredScheme := false
	parseInput := s
	if !strings.Contains(parseInput, "://") {
		if strings.ContainsAny(parseInput, "/?#") {
			parseInput = "http://" + parseInput
			inferredScheme = true
		} else {
			return "", "", false
		}
	}

	u, err := url.Parse(parseInput)
	if err != nil || u == nil {
		return "", "", false
	}
	if u.Scheme == "" || u.Hostname() == "" {
		return "", "", false
	}

	if inferredScheme {
		normalized = u.String()
	} else {
		normalized = s
	}

	canonicalKey = canonicalURLKey(u)
	return normalized, canonicalKey, true
}

func canonicalURLKey(u *url.URL) string {
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	host := normalizeHostname(u.Hostname())
	port := strings.TrimSpace(u.Port())
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	var b strings.Builder
	b.Grow(len(u.String()) + 8)
	b.WriteString("url:")
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	if port != "" {
		b.WriteByte(':')
		b.WriteString(port)
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	b.WriteString(path)
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	return b.String()
}

func normalizeHostPort(seed string) (normalized string, canonicalKey string, ok bool) {
	s := strings.TrimSpace(seed)
	if s == "" {
		return "", "", false
	}
	if strings.Contains(s, "://") {
		return "", "", false
	}
	if strings.ContainsAny(s, "/?#") {
		return "", "", false
	}

	host, port, ok := splitHostPortLoose(s)
	if !ok {
		return "", "", false
	}
	hostNorm := normalizeHostValue(host)
	if hostNorm == "" {
		return "", "", false
	}

	portNum, err := strconv.Atoi(port)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return "", "", false
	}

	normalized = net.JoinHostPort(hostNorm, strconv.Itoa(portNum))
	canonicalKey = "hostport:" + strings.ToLower(hostNorm) + ":" + strconv.Itoa(portNum)
	return normalized, canonicalKey, true
}

func splitHostPortLoose(s string) (host string, port string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if strings.HasPrefix(s, "[") {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return "", "", false
		}
		return h, p, true
	}

	if strings.Count(s, ":") == 1 {
		parts := strings.SplitN(s, ":", 2)
		h := strings.TrimSpace(parts[0])
		p := strings.TrimSpace(parts[1])
		if h == "" || p == "" {
			return "", "", false
		}
		return h, p, true
	}

	if strings.Count(s, ":") > 1 {
		return "", "", false
	}

	return "", "", false
}

func normalizeHost(seed string) (normalized string, canonicalKey string, ok bool) {
	s := strings.TrimSpace(seed)
	if s == "" {
		return "", "", false
	}
	if strings.ContainsAny(s, "/?#") {
		return "", "", false
	}
	if strings.Contains(s, "://") {
		return "", "", false
	}
	if strings.Contains(s, ":") {
		if ip := net.ParseIP(trimBrackets(s)); ip != nil {
			n := ip.String()
			return n, "host:" + n, true
		}
		return "", "", false
	}

	n := normalizeHostValue(s)
	if n == "" {
		return "", "", false
	}
	return n, "host:" + strings.ToLower(n), true
}

func normalizeHostValue(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(trimBrackets(host)); ip != nil {
		return ip.String()
	}
	return normalizeHostname(host)
}

func normalizeHostname(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)
	return host
}

func trimBrackets(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") && len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}
