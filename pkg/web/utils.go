package web

import (
    "bufio"
    "net"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "regexp"
    "sort"
    "strings"
    "time"

    "github.com/zan8in/afrog/v3/pkg/utils"
)

// context keys
type ctxKey string

const (
	ctxUserID    ctxKey = "user_id"
	ctxLoginTime ctxKey = "login_time"
)

func GetUserIDFromContext(r *http.Request) string {
	if v := r.Context().Value(ctxUserID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getClientIP(r *http.Request) string {
	// 仅在受信任反代环境下使用XFF/X-Real-IP（通过环境变量控制）
	if os.Getenv("AFROG_TRUST_PROXY") == "1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.Split(xff, ",")[0]
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	// 默认使用RemoteAddr，防止XFF伪造
	return strings.Split(r.RemoteAddr, ":")[0]
}

func generateRandomPassword() string {
	return utils.CreateRandomString(32)
}

func assetRootDir() (string, error) {
    home, _ := os.UserHomeDir()
    dir := filepath.Join(home, ".config", "afrog", "assets")
    if err := os.MkdirAll(dir, 0o700); err != nil {
        return dir, err
    }
    return dir, nil
}

var safeSegRe = regexp.MustCompile(`^[\p{Han}A-Za-z0-9._-]+$`)

func sanitizeSegment(seg string) (string, bool) {
	s := strings.TrimSpace(seg)
	if s == "" {
		return "", false
	}
	if strings.HasSuffix(s, ".txt") {
		s = strings.TrimSuffix(s, ".txt")
	}
	s = strings.ReplaceAll(s, " ", "-")
	if !safeSegRe.MatchString(s) {
		return "", false
	}
	return s, true
}

func assetFilePathFromID(id string) (string, string, string, error) {
	root, err := assetRootDir()
	if err != nil {
		return "", "", "", err
	}
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "/")
	parts := strings.Split(id, "/")
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		seg, ok := sanitizeSegment(p)
		if !ok {
			return "", "", "", os.ErrInvalid
		}
		cleaned = append(cleaned, seg)
	}
	var category string
	var name string
	if len(cleaned) == 1 {
		name = cleaned[0]
	} else {
		category = strings.Join(cleaned[:len(cleaned)-1], "/")
		name = cleaned[len(cleaned)-1]
	}
	rel := filepath.Join(filepath.FromSlash(category), name+".txt")
	full := filepath.Join(root, rel)
	absRoot, _ := filepath.Abs(root)
	absFull, _ := filepath.Abs(full)
	if !strings.HasPrefix(absFull, absRoot) {
		return "", "", "", os.ErrPermission
	}
	return full, name, category, nil
}

func isValidAddress(line string) bool {
	s := strings.TrimSpace(line)
	if s == "" {
		return false
	}
	schemeRe := regexp.MustCompile(`^(?i)[a-z][a-z0-9+.-]*://\S+$`)
	httpRe := regexp.MustCompile(`^(?i)https?://\S+$`)
	hostPortRe := regexp.MustCompile(`^[A-Za-z0-9.-]+:\d+$`)
	tcpRe := regexp.MustCompile(`^(?i)tcp://[A-Za-z0-9.-]+:\d+$`)
	domainRe := regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
	hostPathRe := regexp.MustCompile(`^(?i)[A-Za-z0-9.-]+(?::\d+)?(?:/\S*)?$`)
	if httpRe.MatchString(s) || hostPortRe.MatchString(s) || tcpRe.MatchString(s) {
		return true
	}
	if schemeRe.MatchString(s) { // 允许任意合法 scheme（如 ftp, udp 等）
		return true
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	if domainRe.MatchString(s) {
		return true
	}
	if hostPathRe.MatchString(s) { // 允许 host[/path] 或 host:port[/path]
		return true
	}
	return false
}

func normalizeAddress(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.HasPrefix(strings.ToLower(s), "http://") || strings.HasPrefix(strings.ToLower(s), "https://") {
		if u, err := url.Parse(s); err == nil {
			host := strings.ToLower(u.Host)
			if strings.Contains(host, ":") {
				h := strings.Split(host, ":")
				host = strings.ToLower(h[0]) + ":" + h[1]
			}
			u.Host = host
			if u.Scheme == "http" && strings.HasSuffix(u.Path, "/") {
				u.Path = strings.TrimRight(u.Path, "/")
			}
			if u.Scheme == "https" && strings.HasSuffix(u.Path, "/") {
				u.Path = strings.TrimRight(u.Path, "/")
			}
			if (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) || (u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) {
				u.Host = strings.Split(u.Host, ":")[0]
			}
			return u.String()
		}
	}
	s = strings.TrimRight(s, "/")
	return strings.ToLower(s)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()
	out := make([]string, 0, 128)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func writeLinesAtomic(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+filepath.Base(path))
	content := strings.Join(lines, "\n")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

func listAssetFiles(root string) ([]AssetSetInfo, error) {
	items := make([]AssetSetInfo, 0, 64)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(d.Name()) != ".txt" {
			return nil
		}
		fi, statErr := os.Stat(p)
		if statErr != nil {
			return statErr
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		base := strings.TrimSuffix(filepath.Base(p), ".txt")
		cat := filepath.ToSlash(filepath.Dir(rel))
		lines, _ := readLines(p)
		items = append(items, AssetSetInfo{
			ID:        strings.TrimSuffix(rel, ".txt"),
			Name:      base,
			Path:      rel,
			Category:  strings.TrimSpace(strings.TrimPrefix(cat, ".")),
			Created:   fi.ModTime().UTC().Format(time.RFC3339),
			Updated:   fi.ModTime().UTC().Format(time.RFC3339),
			LineCount: len(lines),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items, nil
}
