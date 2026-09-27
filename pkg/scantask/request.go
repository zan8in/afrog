package scantask

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/executor"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
)

// Request 描述一次待提交的扫描，字段是 gRPC ScanSpec 与 Web 扫描请求的交集。
//
// 「PoC 来源 → 具体 PoC 路径」的解析规则收在这里而不是各入口，保证 gRPC 与 Web
// 两条路径的扫描范围完全一致（协议文档 §9.1 提到的 poc_source / poc_ids 边界）。
type Request struct {
	Targets []string

	// PoC 选择
	PocSource string // default | curated | my
	PocFile   string
	PocIDs    []string
	Search    string
	Severity  string

	// 性能
	Concurrency    int
	RateLimit      int
	TimeoutSeconds int
	Retries        int
	MaxHostError   int
	Smart          bool

	// 网络
	Proxy           string
	Headers         []string
	FollowRedirects bool

	// 前置阶段
	PortScan          bool
	Ports             string
	SkipHostDiscovery bool
	WebFingerprint    bool

	// OOB
	EnableOOB  bool
	OOBAdapter string

	// 任务元信息
	TaskName     string
	Labels       []string
	NodeSelector string
}

// BuildSpec 把 Request 解析成执行器规格。
//
// 返回的 cleanup 由调用方在任务结束时调用：poc_ids 需要先把 PoC 落成临时目录，
// 该目录随任务结束删除。
//
// PoC 范围语义：
//   - 显式 poc_file / poc_ids，或 poc_source 指向单一来源时 → 独占（-P）；
//   - 未指定来源时 → 在内置 PoC 之上追加 curated / my 目录（-ap）。
func BuildSpec(req Request) (*executor.Spec, func(), error) {
	cleanup := func() {}

	targets := make([]string, 0, len(req.Targets))
	for _, t := range req.Targets {
		if v := strings.TrimSpace(t); v != "" {
			targets = append(targets, v)
		}
	}
	if len(targets) == 0 {
		return nil, cleanup, ErrNoTargets
	}

	source := strings.ToLower(strings.TrimSpace(req.PocSource))
	pocFile := strings.TrimSpace(req.PocFile)

	var appendPocs []string
	if pocFile == "" {
		appendPocs = sourceDirs(source)
	}

	useIDs := false
	if len(req.PocIDs) > 0 {
		dir, created, err := writePocsByID(req.PocIDs)
		if err != nil {
			return nil, cleanup, err
		}
		switch {
		case created > 0:
			pocFile = dir
			useIDs = true
			cleanup = func() { _ = os.RemoveAll(dir) }
		default:
			// 一个都没写成功（ID 全不存在），保持原范围，别留下空目录。
			_ = os.RemoveAll(dir)
		}
	}

	exclusive := useIDs || pocFile != "" || source == "curated" || source == "my"

	spec := &executor.Spec{
		Targets:           targets,
		PocSource:         source,
		PocIDs:            req.PocIDs,
		Concurrency:       req.Concurrency,
		RateLimit:         req.RateLimit,
		TimeoutSeconds:    req.TimeoutSeconds,
		Retries:           req.Retries,
		MaxHostError:      req.MaxHostError,
		Smart:             req.Smart,
		Proxy:             strings.TrimSpace(req.Proxy),
		Headers:           req.Headers,
		FollowRedirects:   req.FollowRedirects,
		PortScan:          req.PortScan,
		Ports:             strings.TrimSpace(req.Ports),
		SkipHostDiscovery: req.SkipHostDiscovery,
		WebFingerprint:    req.WebFingerprint,
		EnableOOB:         req.EnableOOB,
		OOBAdapter:        strings.TrimSpace(req.OOBAdapter),
		TaskName:          strings.TrimSpace(req.TaskName),
		Labels:            req.Labels,
		NodeSelector:      strings.TrimSpace(req.NodeSelector),
	}

	if exclusive {
		// -P 是独占语义且只接受一个路径；单一来源场景下调用方只会给出一个目录。
		if pocFile != "" {
			spec.PocFile = pocFile
		} else if len(appendPocs) > 0 {
			spec.PocFile = appendPocs[0]
		}
	} else {
		spec.AppendPocs = appendPocs
	}

	// poc_ids 已把范围锁死在这批 PoC 上，再叠加 -s/-S 只会缩窄，跳过。
	if !useIDs {
		spec.Search = strings.TrimSpace(req.Search)
		spec.Severity = strings.TrimSpace(req.Severity)
	}

	return spec, cleanup, nil
}

// sourceDirs 返回 PoC 来源对应的目录。
// default 表示「内置 PoC 之上再追加这两个目录」。
func sourceDirs(source string) []string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return nil
	}
	curated := filepath.Join(home, ".config", "afrog", "pocs-curated")
	mine := filepath.Join(home, ".config", "afrog", "pocs-my")
	switch source {
	case "curated":
		return []string{curated}
	case "my":
		return []string{mine}
	default:
		return []string{curated, mine}
	}
}

// writePocsByID 把指定的 PoC 逐个落成文件，返回目录与成功数量。
func writePocsByID(ids []string) (string, int, error) {
	dir, err := os.MkdirTemp("", "afrog-pocids-")
	if err != nil {
		return "", 0, fmt.Errorf("scantask: create poc dir: %w", err)
	}
	created := 0
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		y, err := pocsrepo.ReadYamlByID(id)
		if err != nil || len(y) == 0 {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), y, 0o600); err == nil {
			created++
		}
	}
	return dir, created, nil
}
