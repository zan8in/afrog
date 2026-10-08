package executor

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// buildArgs 把 Spec 映射为 afrog CLI 参数。
//
// 参数名严格取自 pkg/config/options.go 的 flag 定义，语义与 pkg/web/scans.go 的
// Web→SDK 映射保持一致：单个目标用 -t，多个目标写入临时文件后用 -T。
// 返回的 cleanup 由调用方负责调用（用于删除临时目标文件）。
// 无论 Spec 内容如何，末尾一定附加 -json-stream，执行器依赖 NDJSON 事件流。
func buildArgs(taskID string, spec *Spec) (args []string, cleanup func(), err error) {
	cleanup = func() {}
	if spec == nil {
		return nil, cleanup, errors.New("executor: nil spec")
	}

	targets := make([]string, 0, len(spec.Targets))
	for _, tgt := range spec.Targets {
		if v := strings.TrimSpace(tgt); v != "" {
			targets = append(targets, v)
		}
	}
	if len(targets) == 0 {
		return nil, cleanup, errors.New("executor: no targets")
	}

	if len(targets) == 1 {
		args = append(args, "-t", targets[0])
	} else {
		f, ferr := writeTargetsFile(taskID, targets)
		if ferr != nil {
			return nil, cleanup, ferr
		}
		cleanup = func() { _ = os.Remove(f) }
		args = append(args, "-T", f)
	}

	// -P 是独占语义（只扫这里指定的 PoC），-ap 是追加语义（在内置 PoC 之上追加）。
	if v := strings.TrimSpace(spec.PocFile); v != "" {
		args = append(args, "-P", v)
	}
	for _, p := range spec.AppendPocs {
		if v := strings.TrimSpace(p); v != "" {
			args = append(args, "-ap", v)
		}
	}
	if v := strings.TrimSpace(spec.Search); v != "" {
		args = append(args, "-s", v)
	}
	if v := strings.TrimSpace(spec.Severity); v != "" {
		args = append(args, "-S", v)
	}

	if spec.Concurrency > 0 {
		args = append(args, "-c", strconv.Itoa(spec.Concurrency))
	}
	if spec.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(spec.RateLimit))
	}
	if spec.TimeoutSeconds > 0 {
		args = append(args, "-timeout", strconv.Itoa(spec.TimeoutSeconds))
	}
	if spec.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(spec.Retries))
	}
	if spec.MaxHostError > 0 {
		args = append(args, "-mhe", strconv.Itoa(spec.MaxHostError))
	}
	if spec.Smart {
		args = append(args, "-smart")
	}

	// 请求节流：五者互斥，正常由上层保证只设一个；这里按固定优先级兜底。
	switch {
	case spec.ReqLimitPerTarget > 0:
		args = append(args, "-rlt", strconv.Itoa(spec.ReqLimitPerTarget))
	case spec.Polite:
		args = append(args, "-polite")
	case spec.Balanced:
		args = append(args, "-balanced")
	case spec.Aggressive:
		args = append(args, "-aggressive")
	case spec.AutoReqLimit:
		args = append(args, "-auto-req-limit")
	}

	if spec.TaskSmartTimeout {
		args = append(args, "-task-smart-timeout")
	}
	if spec.NoFingerprint {
		args = append(args, "-nf")
	}
	if spec.BreakpointOnVuln {
		args = append(args, "-vsb")
	}
	if spec.MonitorTargets {
		args = append(args, "-mt")
	}
	if v := strings.TrimSpace(spec.Sort); v != "" {
		args = append(args, "-sort", v)
	}
	if spec.BruteMaxRequests > 0 {
		args = append(args, "-brute-max-requests", strconv.Itoa(spec.BruteMaxRequests))
	}
	if spec.MaxRespBodySize > 0 {
		args = append(args, "-mrbs", strconv.Itoa(spec.MaxRespBodySize))
	}

	if v := strings.TrimSpace(spec.Proxy); v != "" {
		args = append(args, "-proxy", v)
	}
	for _, hv := range spec.Headers {
		if v := strings.TrimSpace(hv); v != "" {
			args = append(args, "-H", v)
		}
	}
	// FollowRedirects：CLI 没有对应 flag，Options 里也没有该字段，实际行为由子进程
	// 的 afrog-config.yaml 决定，这里不做映射。

	if spec.PortScan {
		args = append(args, "-ps")
		if v := strings.TrimSpace(spec.Ports); v != "" {
			args = append(args, "-p", v)
		}
	}
	if spec.SkipHostDiscovery {
		args = append(args, "-Pn")
	}
	if spec.WebFingerprint {
		args = append(args, "-w")
	}

	// OOB：CLI 只有 -oob <adapter> 用于选择适配器；key/domain 等凭据来自子进程的
	// afrog-config.yaml（见 pkg/config/oobadapter.go），没有对应 flag，故不映射。
	if spec.EnableOOB {
		if v := strings.TrimSpace(spec.OOBAdapter); v != "" {
			args = append(args, "-oob", v)
		}
		if spec.OOBRateLimit > 0 {
			args = append(args, "-orl", strconv.Itoa(spec.OOBRateLimit))
		}
		if spec.OOBConcurrency > 0 {
			args = append(args, "-oc", strconv.Itoa(spec.OOBConcurrency))
		}
		if spec.OOBPollInterval > 0 {
			args = append(args, "-oob-poll-interval", strconv.Itoa(spec.OOBPollInterval))
		}
		if spec.OOBHitRetention > 0 {
			args = append(args, "-oob-hit-retention", strconv.Itoa(spec.OOBHitRetention))
		}
		if spec.OOBFinalizeTimeout != nil {
			args = append(args, "-oob-finalize-timeout", strconv.Itoa(*spec.OOBFinalizeTimeout))
		}
	}

	// 始终追加：执行器通过 NDJSON 事件流消费子进程输出。
	args = append(args, "-json-stream")

	// 机器驱动的子进程不应往工作目录写 HTML 报告：
	// 结果已进 sqlite 并通过事件流回传，落在 CWD 的报告文件是纯垃圾。
	args = append(args, "-disable-output-html")

	return args, cleanup, nil
}

// writeTargetsFile 把多个目标写入临时文件（每行一个），供 -T 使用。
func writeTargetsFile(taskID string, targets []string) (string, error) {
	prefix := "afrog-targets-"
	if s := sanitizeTaskID(taskID); s != "" {
		prefix += s + "-"
	}
	f, err := os.CreateTemp("", prefix+"*.txt")
	if err != nil {
		return "", fmt.Errorf("executor: create targets file: %w", err)
	}
	if _, err := f.WriteString(strings.Join(targets, "\n") + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("executor: write targets file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("executor: close targets file: %w", err)
	}
	return f.Name(), nil
}

// sanitizeTaskID 把任务 ID 收敛成可安全用作文件名前缀的字符集。
func sanitizeTaskID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := b.String()
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
