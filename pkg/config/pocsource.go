package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/catalog"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
)

// POC 加载失败的原因分类，便于调用方做机器判断而不是匹配错误字符串。
const (
	PocLoadNotFound    = "not_found"
	PocLoadReadFailed  = "read_failed"
	PocLoadParseFailed = "parse_failed"
	PocLoadLegacyOOB   = "legacy_oob"
)

// ErrNoPocMatched 表示路径本身存在，但没有匹配到任何 .yaml/.yml 文件。
var ErrNoPocMatched = errors.New("no poc file matched")

// PocLoadError 描述一个在加载阶段被跳过的 POC。
// 以前这些信息只会被打印到控制台，SDK 调用方无从得知，现在通过诊断列表返回。
type PocLoadError struct {
	// Path 是 POC 文件路径；内置 POC 带 "embedded:" 前缀。
	Path string
	// ID 是解析出的 POC id，解析失败时为空。
	ID string
	// Reason 是 PocLoad* 常量之一。
	Reason string
	// Detail 提供人类可读的补充说明，例如旧 OOB 语法的具体命中项。
	Detail string
	// Err 是底层错误，可能为 nil。
	Err error
}

func (e PocLoadError) Error() string {
	msg := fmt.Sprintf("poc %s: %s", e.Path, e.Reason)
	if e.Detail != "" {
		msg += " (" + e.Detail + ")"
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e PocLoadError) Unwrap() error { return e.Err }

// pocInputs 汇总用户显式指定的 POC 输入。
// PocFile、PocPaths、AppendPoc 三者会被合并，这修复了以前 PocFile 一旦设置
// AppendPoc 就被静默丢弃的问题。
func (o *Options) pocInputs() []string {
	inputs := make([]string, 0, 1+len(o.PocPaths)+len(o.AppendPoc))
	if v := strings.TrimSpace(o.PocFile); v != "" {
		inputs = append(inputs, v)
	}
	for _, p := range o.PocPaths {
		if v := strings.TrimSpace(p); v != "" {
			inputs = append(inputs, v)
		}
	}
	for _, p := range o.AppendPoc {
		if v := strings.TrimSpace(p); v != "" {
			inputs = append(inputs, v)
		}
	}
	return inputs
}

// pocInputsExclusive 表示是否只使用显式指定的 POC，屏蔽内置/curated/my/local 来源。
// PocFile 保留历史语义（独占），PocPaths 则是追加语义。
func (o *Options) pocInputsExclusive() bool {
	return o.PocPathsOnly || strings.TrimSpace(o.PocFile) != ""
}

// ResolvePocInputs 把文件、目录、glob 通配符统一解析成具体的 POC 文件列表。
func ResolvePocInputs(inputs []string) ([]string, []PocLoadError) {
	out := make([]string, 0, len(inputs))
	diags := make([]PocLoadError, 0)
	seen := make(map[string]struct{})

	for _, in := range inputs {
		in = strings.TrimSpace(in)
		if in == "" {
			continue
		}
		paths, err := catalog.New(in).GetPocPath(in)
		if err != nil {
			diags = append(diags, PocLoadError{Path: in, Reason: PocLoadNotFound, Err: err})
			continue
		}
		if len(paths) == 0 {
			diags = append(diags, PocLoadError{Path: in, Reason: PocLoadNotFound, Err: ErrNoPocMatched})
			continue
		}
		for _, p := range paths {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out, diags
}

// ValidatePocInputs 在扫描前校验 POC 输入是否可用。
// 相比直接 os.Stat，它能正确处理 glob 通配符和目录。
func ValidatePocInputs(inputs []string) error {
	if len(inputs) == 0 {
		return nil
	}
	matched, diags := ResolvePocInputs(inputs)
	if len(matched) > 0 {
		return nil
	}
	if len(diags) > 0 {
		return diags[0]
	}
	return ErrNoPocMatched
}

// resolvePocPathItems 返回本次扫描最终要加载的 POC 路径集合。
func (o *Options) resolvePocPathItems() ([]pocsrepo.PathItem, []PocLoadError) {
	explicit, diags := ResolvePocInputs(o.pocInputs())

	// 用户显式指定的 POC 全部保留。ResolvePocInputs 已按绝对路径去重，
	// 这里不能再按文件名去重：不同目录下的同名 POC 是两个不同的 POC，
	// 静默丢弃其中一个会让用户少扫内容且无从察觉。
	items := make([]pocsrepo.PathItem, 0, len(explicit))
	explicitNames := make(map[string]struct{}, len(explicit))
	source := pocsrepo.SourceAppend
	if o.pocInputsExclusive() {
		source = pocsrepo.SourceLocal
	}
	for _, p := range explicit {
		items = append(items, pocsrepo.PathItem{Path: p, Source: source})
		explicitNames[pocBaseName(p)] = struct{}{}
	}

	if o.pocInputsExclusive() {
		return items, diags
	}

	// 合并内置/curated/my/local 来源。同名时以显式指定的为准，
	// 这是"用自己的版本覆盖内置版本"的预期语义。
	base, _ := pocsrepo.CollectOrderedPocPaths(nil)
	for _, it := range base {
		if _, overridden := explicitNames[pocBaseName(it.Path)]; overridden {
			continue
		}
		items = append(items, it)
	}
	return items, diags
}

// pocBaseName 返回 POC 文件名（小写、去扩展名），用于同名覆盖判断。
func pocBaseName(path string) string {
	name := filepath.Base(strings.ReplaceAll(path, "\\", "/"))
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	return strings.ToLower(name)
}
