package executor

// Spec 是扫描规格，字段与协议文档第 6 节 proto 的 ScanSpec 一一对应。
// proto 里为 int32 的字段这里同样用 int，便于直接映射。
//
// PocIDs 与 PocSource 不对应任何 CLI flag：它们需要由调用方（控制面）先解析为
// 具体的 PoC 文件/目录再通过 PocFile 传入，语义与 pkg/web/scans.go 一致——Web 层
// 就是先把 PocIDs 落成临时目录、再把该目录当作 poc_file 交给引擎的。
type Spec struct {
	Targets []string

	// PoC 选择
	PocSource string
	PocIDs    []string
	// PocFile 对应 -P，是独占语义：只扫描这里指定的 PoC。
	PocFile string
	// AppendPocs 对应 -ap，是追加语义：在内置 PoC 之上追加这些目录/文件。
	AppendPocs []string
	Search     string
	Severity   string

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
	OOBKey     string
	OOBDomain  string

	// 任务元信息
	TaskName     string
	Labels       []string
	NodeSelector string
}
