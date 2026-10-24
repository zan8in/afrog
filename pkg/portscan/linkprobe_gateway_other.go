//go:build !linux && !darwin && !windows

package portscan

// 其余平台（plan9、js/wasm 等）没有可用的默认网关读取手段，链路信号关闭，
// 拥塞控制退化为只依赖探测结果。
func defaultGateway() string { return "" }
