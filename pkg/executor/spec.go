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

	// 请求节流：五者互斥（最多一个生效），与 CLI 的 -rlt/-auto-req-limit/-polite/-balanced/-aggressive 对应。
	ReqLimitPerTarget int
	AutoReqLimit      bool
	Polite            bool
	Balanced          bool
	Aggressive        bool

	// 任务级超时与失败保护
	TaskSmartTimeout bool
	NoFingerprint    bool
	// GatingLevel 对应 -gating-level：off|safe|balanced|aggressive。
	// 空表示交给引擎默认（safe）。
	GatingLevel string
	// DryRun 对应 -dry-run：只预演门控决策与归因，不执行任何漏洞 PoC。
	DryRun bool
	// BreakpointOnVuln 对应 -vsb：命中首个漏洞即停止。
	BreakpointOnVuln bool
	MonitorTargets   bool

	// 进阶
	BruteMaxRequests int
	MaxRespBodySize  int

	// Sort 对应 --sort（severity|a-z）。
	Sort string

	// 网络
	Proxy           string
	Headers         []string
	FollowRedirects bool

	// 前置阶段开关统一为三态：nil = 未设置（省略 flag，交回子进程默认值，默认值只在
	// CLI flag 定义处存在一份）、显式 &true / &false = 显式开启 / 关闭。
	// 端口预扫描（-ps）与跳过主机发现（-Pn）CLI 默认关闭，故 nil 即关闭。
	PortScan          *bool
	Ports             string
	SkipHostDiscovery *bool
	// ReportStates 对应 -ps-states：把 closed / filtered 端口也作为结果上报。
	// 仅当 PortScan 显式开启时生效；nil 表示交回子进程默认值（关闭）。这些非开放端口
	// 仅用于展示，不会进入后续扫描目标。
	ReportStates *bool
	// WebFingerprint 控制 Web 探测（-w）阶段。用指针区分「未设置」与「显式关闭」：
	// nil 表示交回子进程默认值（CLI 的 -w 默认开启），只有显式 false 才下发 -w=false。
	// 这样默认值只在 CLI flag 定义处存在一份，各入口无需各自硬编码默认值。
	WebFingerprint *bool
	// WebProbeTimeout 是单次 Web 探测请求与证书获取的超时（秒），0 表示用 CLI 默认值。
	WebProbeTimeout int
	// WebFavicon 开启 favicon 抓取（每个目标多一次请求）。用指针区分「未设置」与「显式关闭」：
	// nil 表示交回子进程默认值（开启，与 CLI 的 -w-favicon 一致），显式 false 才下发 -w-favicon=false。
	WebFavicon *bool
	// WebAssets 对应 -w-assets：Web 探测时最多抓几个首页引用的同源脚本/样式做内容指纹。
	// 用指针区分「未设置」与显式的 0：nil 表示交回子进程默认值（10，即默认开启），
	// 显式 0 表示关闭（把抓取请求省掉），N>0 表示最多抓 N 个。
	WebAssets *int

	// 报告输出：OutputHTML 为真时子进程写 HTML 报告（-o），否则用 -disable-output-html。
	// OutputFile 只是文件名：子进程 CWD 是每任务独立的临时目录，实际路径由执行器固定
	// 到报告目录下（见 buildArgs）。
	OutputHTML bool
	OutputFile string

	// NoSaveDB 对应 -no-save-db：命中只走控制台/事件流，不写入 result 表。
	// 默认 false（写库），用于测试性扫描时保持漏洞报告与台账干净。
	NoSaveDB bool

	// OOB
	EnableOOB  bool
	OOBAdapter string
	OOBKey     string
	OOBDomain  string
	// OOB 调优；OOBFinalizeTimeout 用指针区分「未设置」与显式的 0/-1。
	OOBRateLimit       int
	OOBConcurrency     int
	OOBPollInterval    int
	OOBHitRetention    int
	OOBFinalizeTimeout *int

	// 任务元信息
	TaskName     string
	Labels       []string
	NodeSelector string
}

// BoolPtr 返回 v 的指针，便于给三态开关字段（如 WebFingerprint）显式赋值：
// nil = 未设置（交回子进程默认值），&true / &false = 显式开启 / 关闭。
func BoolPtr(v bool) *bool { return &v }
