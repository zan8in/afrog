package web

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/zan8in/afrog/v3/pkg/guard"
	"github.com/zan8in/gologger"
)

// 高危动作闸门的落盘审计。
//
// 内存里的审计（guard.Policy.audit）重启即清，这条链路补的是「重启后仍能看到
// 谁被拒绝、谁被放行」。用 JSONL 追加而不是建表：裁决是低频事件，追加写足够，
// 也省掉一套 SQLite schema 与迁移。
//
// 保留策略：文件超过 securityAuditMaxBytes 时只保留最近 securityAuditKeep 条。
const (
	securityAuditFileName = "guard_audit.jsonl"
	securityAuditMaxBytes = 1 << 20 // 1MB
	securityAuditKeep     = 1000
	securityAuditReturn   = 200
)

var (
	securityAuditMu sync.Mutex
	// securityAuditPathOverride 供测试指定临时文件，避免写用户目录。
	securityAuditPathOverride string
)

func securityAuditFilePath() (string, error) {
	if securityAuditPathOverride != "" {
		return securityAuditPathOverride, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "afrog")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, securityAuditFileName), nil
}

// appendGuardAudit 追加一条裁决。失败只记 Debug，绝不影响动作本身——
// 审计是旁路能力，不能因为它写不进去就让派发或探针失败。
func appendGuardAudit(entry guard.Entry) {
	securityAuditMu.Lock()
	defer securityAuditMu.Unlock()

	path, err := securityAuditFilePath()
	if err != nil {
		gologger.Debug().Msgf("闸门审计路径不可用: %v", err)
		return
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		gologger.Debug().Msgf("写入闸门审计失败: %v", err)
		return
	}
	_, werr := f.Write(append(line, '\n'))
	_ = f.Close()
	if werr != nil {
		gologger.Debug().Msgf("写入闸门审计失败: %v", werr)
		return
	}
	if st, err := os.Stat(path); err == nil && st.Size() > securityAuditMaxBytes {
		trimGuardAudit(path)
	}
}

// trimGuardAudit 只保留最近 securityAuditKeep 条，按原文件顺序重写。
func trimGuardAudit(path string) {
	entries := readGuardAuditAsc(path, securityAuditKeep)
	if len(entries) == 0 {
		return
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		_, _ = w.Write(append(b, '\n'))
	}
	_ = w.Flush()
	_ = f.Close()
	_ = os.Rename(tmp, path)
}

// loadGuardAudit 读取最近 limit 条裁决，最新的在前，供界面直接展示。
func loadGuardAudit(limit int) []guard.Entry {
	securityAuditMu.Lock()
	defer securityAuditMu.Unlock()

	path, err := securityAuditFilePath()
	if err != nil {
		return nil
	}
	asc := readGuardAuditAsc(path, limit)
	out := make([]guard.Entry, len(asc))
	for i := range asc {
		out[len(asc)-1-i] = asc[i]
	}
	return out
}

// readGuardAuditAsc 按文件顺序读取最后 keep 条。
// 掉电可能留下半行，解析失败的整行直接跳过即可。
func readGuardAuditAsc(path string, keep int) []guard.Entry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	entries := make([]guard.Entry, 0, keep)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		var e guard.Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if len(entries) > keep {
		entries = entries[len(entries)-keep:]
	}
	return entries
}
