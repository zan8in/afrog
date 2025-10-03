package pocsrepo

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pocs"
)

// Source 表示 POC 来源
type Source string

const (
	SourceBuiltin Source = "builtin" // 内置嵌入
	SourceCurated Source = "curated"
	SourceMy      Source = "my"
	SourceLocal   Source = "local"
	SourceAppend  Source = "append"
)

// 统一的 POC 元信息项（列表用）
type Item struct {
	ID       string
	Name     string
	Severity string
	Author   []string
	Tags     []string
	Source   Source
	Path     string // builtin: "embedded:<path>", 其他为本地路径（~ 开头）
	Created  string
}

// 统一的路径项（扫描与 -pl 用）
type PathItem struct {
	Path   string
	Source Source
}

// 列表查询参数
type ListOptions struct {
	Source   string   // builtin|curated|my|all
	Severity []string // 过滤等级
	Tags     []string // 过滤标签
	Authors  []string // 过滤作者
	Q        string   // 关键词（id/name/tags/author 模糊）
}

// 初始化（确保用户目录）
func Init() {
	// 当前 poc 包 init 已做本地目录初始化，这里补充保证
	poc.EnsureCuratedAndMyPocDirectories()
}

// 列出 POC 元信息（已去重、过滤、排序）
func ListMeta(opts ListOptions) ([]Item, error) {
	switch opts.Source {
	case "builtin", "curated", "my", "all":
	default:
		opts.Source = "all"
	}

	sources := []Source{}
	switch opts.Source {
	case "builtin":
		// builtin = append + local + builtin
		sources = []Source{SourceAppend, SourceLocal, SourceBuiltin}
	case "curated":
		sources = []Source{SourceCurated}
	case "my":
		sources = []Source{SourceMy}
	case "all":
		// all/默认 = curated + my + (append + local + builtin)
		// 遍历顺序决定去重优先级：curated > my > append > local > builtin
		sources = []Source{SourceCurated, SourceMy, SourceAppend, SourceLocal, SourceBuiltin}
	}

	seen := map[string]struct{}{}
	items := make([]Item, 0, 2048)

	for _, src := range sources {
		switch src {
		case SourceBuiltin:
			for _, ep := range pocs.EmbedFileList {
				pm, err := pocs.EmbedReadPocMetaByPath(ep)
				if err != nil {
					continue
				}
				it := Item{
					ID:       pm.Id,
					Name:     pm.Info.Name,
					Severity: normalizeSeverity(pm.Info.Severity),
					Author:   SplitAuthors(pm.Info.Author),
					Tags:     SplitTags(pm.Info.Tags),
					Source:   SourceBuiltin,
					Path:     "embedded:" + ep,
					Created:  pm.Info.Created,
				}
				key := makeKey(it)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				items = append(items, it)
			}

		case SourceCurated:
			home, _ := os.UserHomeDir()
			dir := filepath.Join(home, "afrog-curated-pocs")
			files, _ := poc.LocalWalkFiles(dir)
			for _, lp := range files {
				pm, err := poc.LocalReadPocMetaByPath(lp)
				if err != nil {
					continue
				}
				it := Item{
					ID:       pm.Id,
					Name:     pm.Info.Name,
					Severity: normalizeSeverity(pm.Info.Severity),
					Author:   SplitAuthors(pm.Info.Author),
					Tags:     SplitTags(pm.Info.Tags),
					Source:   SourceCurated,
					Path:     strings.Replace(lp, home, "~", 1),
					Created:  pm.Info.Created,
				}
				key := makeKey(it)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				items = append(items, it)
			}

		case SourceMy:
			home, _ := os.UserHomeDir()
			dir := filepath.Join(home, "afrog-my-pocs")
			files, _ := poc.LocalWalkFiles(dir)
			for _, lp := range files {
				pm, err := poc.LocalReadPocMetaByPath(lp)
				if err != nil {
					continue
				}
				it := Item{
					ID:       pm.Id,
					Name:     pm.Info.Name,
					Severity: normalizeSeverity(pm.Info.Severity),
					Author:   SplitAuthors(pm.Info.Author),
					Tags:     SplitTags(pm.Info.Tags),
					Source:   SourceMy,
					Path:     strings.Replace(lp, home, "~", 1),
					Created:  pm.Info.Created,
				}
				key := makeKey(it)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				items = append(items, it)
			}

		case SourceLocal:
			home, _ := os.UserHomeDir()
			files, _ := poc.LocalWalkFiles(poc.LocalPocDirectory)
			for _, lp := range files {
				pm, err := poc.LocalReadPocMetaByPath(lp)
				if err != nil {
					continue
				}
				it := Item{
					ID:       pm.Id,
					Name:     pm.Info.Name,
					Severity: normalizeSeverity(pm.Info.Severity),
					Author:   SplitAuthors(pm.Info.Author),
					Tags:     SplitTags(pm.Info.Tags),
					Source:   SourceLocal,
					Path:     strings.Replace(lp, home, "~", 1),
					Created:  pm.Info.Created,
				}
				key := makeKey(it)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				items = append(items, it)
			}

		case SourceAppend:
			home, _ := os.UserHomeDir()
			// 遍历追加目录/文件，统一读取元信息
			for _, entry := range poc.LocalAppendList {
				// 先尝试按目录收集文件
				files, _ := poc.LocalWalkFiles(entry)
				if len(files) == 0 {
					// 非目录或遍历为空时，尝试作为单文件处理
					pm, err := poc.LocalReadPocMetaByPath(entry)
					if err == nil {
						it := Item{
							ID:       pm.Id,
							Name:     pm.Info.Name,
							Severity: normalizeSeverity(pm.Info.Severity),
							Author:   SplitAuthors(pm.Info.Author),
							Tags:     SplitTags(pm.Info.Tags),
							Source:   SourceAppend,
							Path:     strings.Replace(entry, home, "~", 1),
							Created:  pm.Info.Created,
						}
						key := makeKey(it)
						if _, ok := seen[key]; ok {
							continue
						}
						seen[key] = struct{}{}
						items = append(items, it)
					}
					continue
				}
				for _, lp := range files {
					pm, err := poc.LocalReadPocMetaByPath(lp)
					if err != nil {
						continue
					}
					it := Item{
						ID:       pm.Id,
						Name:     pm.Info.Name,
						Severity: normalizeSeverity(pm.Info.Severity),
						Author:   SplitAuthors(pm.Info.Author),
						Tags:     SplitTags(pm.Info.Tags),
						Source:   SourceAppend,
						Path:     strings.Replace(lp, home, "~", 1),
						Created:  pm.Info.Created,
					}
					key := makeKey(it)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					items = append(items, it)
				}
			}
		}
	}

	// 过滤
	sevSet := toLowerSet(opts.Severity)
	tagSet := toRawSet(opts.Tags)
	authSet := toRawSet(opts.Authors)
	q := strings.ToLower(strings.TrimSpace(opts.Q))

	filtered := items[:0]
	for _, it := range items {
		if len(sevSet) > 0 {
			if _, ok := sevSet[strings.ToLower(it.Severity)]; !ok {
				continue
			}
		}
		if len(tagSet) > 0 && !matchesAny(it.Tags, tagSet) {
			continue
		}
		if len(authSet) > 0 && !matchesAny(it.Author, authSet) {
			continue
		}
		if q != "" {
			if !containsAny([]string{strings.ToLower(it.ID), strings.ToLower(it.Name)}, q) &&
				!sliceContainsSubstring(stringsToLower(it.Tags), q) &&
				!sliceContainsSubstring(stringsToLower(it.Author), q) {
				continue
			}
		}
		filtered = append(filtered, it)
	}

	// 排序：severity -> name
	sort.Slice(filtered, func(i, j int) bool {
		si, sj := severityRank(filtered[i].Severity), severityRank(filtered[j].Severity)
		if si != sj {
			return si < sj
		}
		return strings.ToLower(filtered[i].Name) < strings.ToLower(filtered[j].Name)
	})

	return filtered, nil
}

// CollectOrderedPocPaths 提供统一路径整合与去重，供扫描与 -pl 使用
// 优先级：curated > my > append > local > builtin
func CollectOrderedPocPaths(appendDirs []string) ([]PathItem, error) {
	out := []PathItem{}
	seen := map[string]Source{} // filename base -> src

	add := func(path string, src Source) {
		fname := filepath.Base(strings.ReplaceAll(path, "\\", "/"))
		base := strings.TrimSuffix(strings.TrimSuffix(fname, ".yaml"), ".yml")
		if prev, ok := seen[base]; ok {
			if srcPriority(src) >= srcPriority(prev) {
				return
			}
		}
		seen[base] = src
		out = append(out, PathItem{Path: path, Source: src})
	}

	home, _ := os.UserHomeDir()

	// curated
	curDir := filepath.Join(home, "afrog-curated-pocs")
	curFiles, _ := poc.LocalWalkFiles(curDir)
	for _, p := range curFiles {
		add(p, SourceCurated)
	}

	// my
	myDir := filepath.Join(home, "afrog-my-pocs")
	myFiles, _ := poc.LocalWalkFiles(myDir)
	for _, p := range myFiles {
		add(p, SourceMy)
	}

	// append
	for _, dir := range appendDirs {
		files, _ := poc.LocalWalkFiles(dir)
		for _, p := range files {
			add(p, SourceAppend)
		}
	}

	// local
	locFiles, _ := poc.LocalWalkFiles(poc.LocalPocDirectory)
	for _, p := range locFiles {
		add(p, SourceLocal)
	}

	// builtin
	for _, ep := range pocs.EmbedFileList {
		add("embedded:"+ep, SourceBuiltin)
	}

	// 稳定排序：按来源优先级 -> 文件名
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := srcPriority(out[i].Source), srcPriority(out[j].Source)
		if pi != pj {
			return pi < pj
		}
		return strings.ToLower(filepath.Base(out[i].Path)) < strings.ToLower(filepath.Base(out[j].Path))
	})

	return out, nil
}

// ---- helpers ----

func makeKey(it Item) string {
	if it.ID != "" {
		return strings.ToLower(it.ID)
	}
	base := filepath.Base(strings.ReplaceAll(it.Path, "\\", "/"))
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
	return strings.ToLower(base)
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(s)
	default:
		return "info"
	}
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4 // info
	}
}

func srcPriority(s Source) int {
	switch s {
	case SourceCurated:
		return 0
	case SourceMy:
		return 1
	case SourceAppend:
		return 2
	case SourceLocal:
		return 3
	default:
		return 4 // builtin
	}
}

func SplitTags(tags string) []string {
	if tags == "" {
		return nil
	}
	parts := strings.Split(tags, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func SplitAuthors(authors string) []string {
	if authors == "" {
		return nil
	}
	parts := strings.Split(authors, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		a := strings.TrimSpace(p)
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func toLowerSet(list []string) map[string]struct{} {
	if len(list) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(list))
	for _, v := range list {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			m[v] = struct{}{}
		}
	}
	return m
}

func toRawSet(list []string) map[string]struct{} {
	if len(list) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(list))
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v != "" {
			m[v] = struct{}{}
		}
	}
	return m
}

func matchesAny(list []string, set map[string]struct{}) bool {
	if len(set) == 0 {
		return true
	}
	for _, v := range list {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

func stringsToLower(list []string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		out = append(out, strings.ToLower(v))
	}
	return out
}

func containsAny(vals []string, q string) bool {
	for _, v := range vals {
		if strings.Contains(v, q) {
			return true
		}
	}
	return false
}

func sliceContainsSubstring(list []string, q string) bool {
	for _, v := range list {
		if strings.Contains(v, q) {
			return true
		}
	}
	return false
}