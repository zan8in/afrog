package runner

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	fileutil "github.com/zan8in/pins/file"
)

var PoCScanProgress []string

// webProbeLinePrefix 是 Web 探测结果在断点文件里的行前缀。
//
// Web 探测的结果不能只记「做过了」：恢复时必须把 URL、指纹、WAF 这些结论一并灌回引擎，
// 否则 requires 门控会因为指纹丢失而把整批 PoC 误跳过——那比重新探测更糟。
const webProbeLinePrefix = "wp:"

// webProbeRecord 是断点文件里的一行 Web 探测结果（JSON 单行，无换行）。
type webProbeRecord struct {
	Key  string  `json:"key"`
	Meta WebMeta `json:"meta"`
}

type ScanProgress struct {
	mergedProgress  map[string]struct{} // 合并后的完整进度
	resumeProgress  []string            // 原始恢复文件中的进度
	currentProgress []string            // 当前扫描新增进度
	DoneTasks       uint32              // 已完成任务数（用于恢复进度显示）
	TotalTasks      uint32              // 总任务数（用于展示/诊断）
	perPocTasks     map[string]map[string]struct{}
	// webProbes 是已完成的 Web 探测结论，key 与引擎内的 webMetaByKey 一致。
	webProbes map[string]WebMeta
	mutex     sync.Mutex
	saveMutex sync.Mutex
}

func pocKey(pocID string) string {
	return "poc:" + pocID
}

func taskKey(pocID, target string) string {
	h := sha1.Sum([]byte(target))
	return "tp:" + pocID + ":" + hex.EncodeToString(h[:])
}

func NewScanProgress(resume string) (*ScanProgress, error) {
	sp := &ScanProgress{
		mergedProgress:  make(map[string]struct{}),
		resumeProgress:  make([]string, 0),
		currentProgress: make([]string, 0),
		perPocTasks:     make(map[string]map[string]struct{}),
		webProbes:       make(map[string]WebMeta),
	}

	if len(resume) > 0 {
		if rsChan, err := fileutil.ReadFile(resume); err == nil {
			for r := range rsChan {
				line := strings.TrimSpace(r)
				if line == "" {
					continue
				}
				if strings.HasPrefix(line, "@done_tasks=") {
					v := strings.TrimPrefix(line, "@done_tasks=")
					if n, e := strconv.ParseUint(strings.TrimSpace(v), 10, 32); e == nil {
						sp.DoneTasks = uint32(n)
					}
					continue
				}
				if strings.HasPrefix(line, "@total_tasks=") {
					v := strings.TrimPrefix(line, "@total_tasks=")
					if n, e := strconv.ParseUint(strings.TrimSpace(v), 10, 32); e == nil {
						sp.TotalTasks = uint32(n)
					}
					continue
				}

				// Web 探测结论整行是 JSON，必须在按逗号切分之前认出来，
				// 否则 URL 里的逗号会把这一行拆碎。
				if strings.HasPrefix(line, webProbeLinePrefix) {
					var rec webProbeRecord
					payload := strings.TrimPrefix(line, webProbeLinePrefix)
					if e := json.Unmarshal([]byte(payload), &rec); e == nil && rec.Key != "" {
						sp.webProbes[rec.Key] = rec.Meta
					}
					continue
				}

				if strings.Contains(line, ",") {
					list := strings.Split(line, ",")
					for _, raw := range list {
						id := strings.TrimSpace(raw)
						if id == "" || strings.HasPrefix(id, "@") {
							continue
						}
						k := pocKey(id)
						sp.mergedProgress[k] = struct{}{}
						sp.resumeProgress = append(sp.resumeProgress, k)
					}
					continue
				}

				id := strings.TrimSpace(line)
				if id == "" || strings.HasPrefix(id, "@") {
					continue
				}
				if strings.HasPrefix(id, "tp:") {
					sp.mergedProgress[id] = struct{}{}
					sp.resumeProgress = append(sp.resumeProgress, id)
					parts := strings.SplitN(strings.TrimPrefix(id, "tp:"), ":", 2)
					if len(parts) >= 1 {
						pocID := parts[0]
						if _, ok := sp.perPocTasks[pocID]; !ok {
							sp.perPocTasks[pocID] = make(map[string]struct{})
						}
						sp.perPocTasks[pocID][id] = struct{}{}
					}
					continue
				}
				if strings.HasPrefix(id, "poc:") {
					sp.mergedProgress[id] = struct{}{}
					sp.resumeProgress = append(sp.resumeProgress, id)
					continue
				}

				k := pocKey(id)
				sp.mergedProgress[k] = struct{}{}
				sp.resumeProgress = append(sp.resumeProgress, k)
			}
		}
	}

	if sp.DoneTasks == 0 {
		// 如果未保存 done_tasks 元信息，但存在 target+PoC 级 key，则用其数量恢复进度显示
		n := uint32(0)
		for k := range sp.mergedProgress {
			if strings.HasPrefix(k, "tp:") {
				n++
			}
		}
		if n > 0 {
			sp.DoneTasks = n
		}
	}

	return sp, nil
}

func (p *ScanProgress) IncrementTask(pocID, target string) {
	k := taskKey(pocID, target)
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if _, exists := p.mergedProgress[k]; exists {
		return
	}
	p.mergedProgress[k] = struct{}{}
	p.currentProgress = append(p.currentProgress, k)
	if _, ok := p.perPocTasks[pocID]; !ok {
		p.perPocTasks[pocID] = make(map[string]struct{})
	}
	p.perPocTasks[pocID][k] = struct{}{}
}

func (p *ScanProgress) MarkPocDone(pocID string) {
	k := pocKey(pocID)
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if tasks, ok := p.perPocTasks[pocID]; ok {
		for tk := range tasks {
			delete(p.mergedProgress, tk)
		}
		delete(p.perPocTasks, pocID)
	}
	if _, exists := p.mergedProgress[k]; exists {
		return
	}
	p.mergedProgress[k] = struct{}{}
	p.currentProgress = append(p.currentProgress, k)
}

func (p *ScanProgress) ContainsPoc(pocID string) bool {
	k := pocKey(pocID)
	p.mutex.Lock()
	defer p.mutex.Unlock()
	_, exists := p.mergedProgress[k]
	return exists
}

func (p *ScanProgress) ContainsTask(pocID, target string) bool {
	k := taskKey(pocID, target)
	p.mutex.Lock()
	defer p.mutex.Unlock()
	_, exists := p.mergedProgress[k]
	return exists
}

func (p *ScanProgress) Increment(id string) {
	// 保留旧接口：将 id 视为 pocID
	p.MarkPocDone(id)
}

func (p *ScanProgress) Contains(id string) bool {
	// 保留旧接口：将 id 视为 pocID
	return p.ContainsPoc(id)
}

// RecordWebProbe 记录一条已完成的 Web 探测结论（key 与引擎内 webMetaByKey 同一口径）。
func (p *ScanProgress) RecordWebProbe(key string, meta WebMeta) {
	if p == nil || key == "" {
		return
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.webProbes == nil {
		p.webProbes = make(map[string]WebMeta)
	}
	p.webProbes[key] = meta
}

// ResumedWebProbes 返回断点文件里已完成的 Web 探测结论；没有时返回 nil。
func (p *ScanProgress) ResumedWebProbes() map[string]WebMeta {
	if p == nil {
		return nil
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if len(p.webProbes) == 0 {
		return nil
	}
	out := make(map[string]WebMeta, len(p.webProbes))
	for k, v := range p.webProbes {
		out[k] = v
	}
	return out
}

// 新增方法：原子化保存到指定文件
func (p *ScanProgress) AtomicSave(filename string, doneTasks, totalTasks uint32) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	buf := bytes.NewBuffer(nil)
	buf.WriteString("@done_tasks=")
	buf.WriteString(strconv.FormatUint(uint64(doneTasks), 10))
	buf.WriteString("\n")
	buf.WriteString("@total_tasks=")
	buf.WriteString(strconv.FormatUint(uint64(totalTasks), 10))
	buf.WriteString("\n")

	// Web 探测结论整体回灌：只记「探测过了」没用，恢复时引擎必须拿到 URL 与指纹，
	// 否则 requires 门控会因指纹缺失把整批 PoC 误跳过。排序只是为了让文件内容稳定，
	// 便于 diff 与人工排查。
	if len(p.webProbes) > 0 {
		keys := make([]string, 0, len(p.webProbes))
		for k := range p.webProbes {
			if k != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			payload, err := json.Marshal(webProbeRecord{Key: k, Meta: p.webProbes[k]})
			if err != nil {
				continue
			}
			buf.WriteString(webProbeLinePrefix)
			buf.Write(payload)
			buf.WriteString("\n")
		}
	}

	for id := range p.mergedProgress {
		if id == "" || strings.HasPrefix(id, "@") {
			continue
		}
		buf.WriteString(id)
		buf.WriteString("\n")
	}

	// 空数据不保存
	if buf.Len() == 0 {
		return nil
	}

	// 文件操作专用锁
	p.saveMutex.Lock()
	defer p.saveMutex.Unlock()

	// 使用临时文件保证原子性
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0666); err != nil {
		return err
	}

	// 原子替换文件
	return os.Rename(tmpFile, filename)
}

// ---- legacy (kept for compatibility) ----

// Deprecated: use IncrementTask/MarkPocDone
// func (p *ScanProgress) String() string {
// 	return strings.Join(p.progress, ",")
// }

// Deprecated: replaced by AtomicSave(filename, doneTasks, totalTasks)
// func (p *ScanProgress) AtomicSave(filename string) error { ... }
