package utils

// 阶段标签统一小写，与 `[INF] 阶段` 运维行、进度行保持同一套写法；
// 长度统一为 9 字符，正好对齐进度行的 `%-9s` 列。
const (
	StageHostDiscovery = "host-disc"
	StagePortScan      = "port-scan"
	StageWebProbe      = "web-probe"
	StageVulnScan      = "vuln-scan"
)
