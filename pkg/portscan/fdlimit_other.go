//go:build !unix && !windows

package portscan

// 其余平台（plan9、js/wasm 等）既没有 RLIMIT_NOFILE，也没有对应的资源耗尽错误码
// 判定口径。这里保持保守：不做启动预算、不做自动提升、不把任何错误归因为本机资源
// 耗尽，全部交给默认的错误分类处理。

func fdScanBudget() int { return 0 }

func raiseFDLimit() (uint64, bool) { return 0, false }

func isFDExhausted(err error) bool { return false }

func fdAdvice() string { return "lower -prate" }
