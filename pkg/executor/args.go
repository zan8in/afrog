package executor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	default:
		// CLI 现在默认开启自适应限速。这里显式关闭，让 Web 端保持「未选择任何档位
		// 即不限速」的既有语义，不随 CLI 默认值的变化而漂移。
		args = append(args, "-auto-req-limit=false")
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
		if spec.ReportStates {
			args = append(args, "-ps-states")
		}
	}
	if spec.SkipHostDiscovery {
		args = append(args, "-Pn")
	}
	if spec.WebFingerprint {
		args = append(args, "-w")
	} else {
		// CLI 的 -w 现在默认开启，因此「不要 Web 探测」必须显式关掉：
		// 只省略这个 flag 等于把决定权交回子进程默认值，Web 控制台里关闭探测会失效。
		args = append(args, "-w=false")
	}
	// 探测阶段的细粒度参数：0/未开启时省略，让子进程用自己的默认值。
	if spec.WebProbeTimeout > 0 {
		args = append(args, "-w-timeout", strconv.Itoa(spec.WebProbeTimeout))
	}
	if spec.WebFavicon {
		args = append(args, "-w-favicon")
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

	// 默认不让机器驱动的子进程写 HTML 报告：结果已进 sqlite 并通过事件流回传，
	// 落在 CWD（每任务临时目录）的报告是纯垃圾。显式开启才写，且路径固定在报告目录下。
	reportPath := ""
	if spec.OutputHTML {
		// 报告路径解析失败（如取不到 home 目录）不应拖垮扫描，静默回退到不生成。
		reportPath, _ = reportFilePath(taskID, spec.OutputFile)
	}
	if reportPath != "" {
		args = append(args, "-o", reportPath)
	} else {
		args = append(args, "-disable-output-html")
	}

	// 结果写库：子进程默认写库，故只在关闭时显式下发，语义与 CLI 的默认值一致。
	if spec.NoSaveDB {
		args = append(args, "-no-save-db")
	}

	return args, cleanup, nil
}

// ReportsDir 返回 HTML 报告的统一落盘目录：控制面进程当前目录下的 ./reports。
//
// 与 afrog CLI 的口径一致（report.OutputDirectory），但不直接交给子进程一个相对路径：
// 子进程的 CWD 是每任务独立的临时目录，相对路径的报告会随临时目录一起删除，所以这里
// 解析成绝对路径后再通过 -o 传下去。目录固定而不由前端指定，避免写坏宿主机任意路径。
func ReportsDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("executor: resolve working dir: %w", err)
	}
	dir := filepath.Join(wd, "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("executor: create reports dir: %w", err)
	}
	return dir, nil
}

// reportFilePath 把前端给的文件名收敛成报告目录下的绝对路径。
//
// 只取基名并过滤不安全字符，杜绝路径穿越；留空时用任务号 + 时间戳兜底命名，保证
// 并发任务不会互相覆盖。
func reportFilePath(taskID, name string) (string, error) {
	dir, err := ReportsDir()
	if err != nil {
		return "", err
	}
	base := sanitizeReportName(name)
	if base == "" {
		prefix := "afrog-report-"
		if s := sanitizeTaskID(taskID); s != "" {
			prefix += s + "-"
		}
		base = prefix + time.Now().Format("20060102-150405") + ".html"
	}
	return filepath.Join(dir, base), nil
}

// sanitizeReportName 把用户给的报告名收敛成可安全用作文件名的字符串。
// 返回空串表示「没有可用的名字」，由调用方兜底命名。
func sanitizeReportName(name string) string {
	// 先取基名，避免 "../../etc/x" 这类路径穿越。
	v := filepath.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == ' ':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "._- ")
	if len(s) > 80 {
		s = s[:80]
	}
	if strings.Trim(s, "._- ") == "" {
		return ""
	}
	// afrog 的 -o 只接受 .html/.htm，其余一律补上 .html
	lower := strings.ToLower(s)
	if !strings.HasSuffix(lower, ".html") && !strings.HasSuffix(lower, ".htm") {
		s += ".html"
	}
	return s
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
