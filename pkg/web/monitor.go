package web

import (
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/zan8in/gologger"
)

type SystemMonitor struct {
	cpuUsage    float64
	memoryUsage float64
	mu          sync.RWMutex
	stopChan    chan struct{}
}

var globalMonitor *SystemMonitor

// InitMonitor 初始化并启动监控
func InitMonitor() {
	globalMonitor = &SystemMonitor{
		stopChan: make(chan struct{}),
	}
	go globalMonitor.start()
}

// StopMonitor 停止监控
func StopMonitor() {
	if globalMonitor != nil {
		close(globalMonitor.stopChan)
	}
}

func (m *SystemMonitor) start() {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err != nil {
		gologger.Error().Msgf("Failed to get process info: %v", err)
		return
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			// 获取 CPU 使用率 (0 表示计算自上次调用以来的平均值)
			cpu, err := proc.Percent(0)
			if err == nil {
				m.mu.Lock()
				m.cpuUsage = cpu
				m.mu.Unlock()
			}

			// 获取内存使用率
			memPercent, err := proc.MemoryPercent()
			if err == nil {
				m.mu.Lock()
				m.memoryUsage = float64(memPercent)
				m.mu.Unlock()
			}
		}
	}
}

// GetMonitorStats 获取当前的 CPU 和内存使用率
func GetMonitorStats() (float64, float64) {
	if globalMonitor == nil {
		return 0, 0
	}
	globalMonitor.mu.RLock()
	defer globalMonitor.mu.RUnlock()
	return globalMonitor.cpuUsage, globalMonitor.memoryUsage
}
