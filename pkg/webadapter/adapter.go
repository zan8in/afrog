package webadapter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zan8in/afrog/v3"
	"github.com/zan8in/afrog/v3/pkg/db"
	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
	"github.com/zan8in/afrog/v3/pkg/pocsrepo"
	"github.com/zan8in/afrog/v3/pkg/result"
	"github.com/zan8in/afrog/v3/pkg/web"
	"github.com/zan8in/gologger"
)

// RegisterAfrogWebRunner 显式注册 Web 任务执行器（基于 afrog SDK）
func RegisterAfrogWebRunner() {
	gologger.Info().Msg("RegisterAfrogWebRunner: registering afrog SDK runner")
	web.RegisterTaskScanRunner(func(ctx context.Context, in web.TaskScanInput, cb web.TaskScanCallbacks) error {
		// 将 web 任务ID绑定到SQLite写入（全局 TaskID）
		db.TaskID = in.TaskID
		gologger.Info().Msgf("SDK Runner Start: task_id=%s poc_ids=%v targets=%v", in.TaskID, in.PocIDs, in.Targets)

		// 准备临时 POC 目录（将指定 PocIDs 的 YAML 写入）
		pocsDir, err := writeTempPocsDir(in.PocIDs)
		if err != nil {
			if cb.OnError != nil {
				cb.OnError(fmt.Sprintf("准备临时POC目录失败: %v", err))
			}
			if cb.OnEnded != nil {
				cb.OnEnded(web.StatusFailed)
			}
			gologger.Error().Msgf("SDK Runner: writeTempPocsDir failed: %v", err)
			return err
		}
		defer os.RemoveAll(pocsDir)
		gologger.Info().Msgf("SDK Runner: temp pocs dir prepared: %s", pocsDir)

		// 构建并创建 SDK 扫描器
		opts := afrog.NewSDKOptions()
		opts.Targets = in.Targets
		opts.PocFile = pocsDir
		// 映射 Web TaskOptions -> SDKOptions（可按需扩展）
		if in.Options.Timeout > 0 {
			opts.Timeout = in.Options.Timeout
		}
		if in.Options.Concurrency > 0 {
			opts.Concurrency = in.Options.Concurrency
		}
		// 使用统计轮询而非通道
		opts.EnableStream = false

		scanner, err := afrog.NewSDKScanner(opts)
		if err != nil {
			if cb.OnError != nil {
				cb.OnError(fmt.Sprintf("初始化扫描器失败: %v", err))
			}
			if cb.OnEnded != nil {
				cb.OnEnded(web.StatusFailed)
			}
			gologger.Error().Msgf("SDK Runner: NewSDKScanner failed: %v", err)
			return err
		}
		defer scanner.Close()
		gologger.Info().Msgf("SDK Runner: scanner created: targets=%d pocs_dir=%s timeout=%d concurrency=%d", len(opts.Targets), pocsDir, opts.Timeout, opts.Concurrency)

		// 漏洞结果回调：推送到 SSE + 写入 SQLite
		scanner.OnResult = func(r *result.Result) {
			latency := 0
			if len(r.AllPocResult) > 0 {
				last := r.AllPocResult[len(r.AllPocResult)-1]
				if last != nil && last.ResultResponse != nil {
					latency = int(last.ResultResponse.GetLatency())
				}
			}
			item := web.ResultItem{
				Target:    r.Target,
				PocID:     r.PocInfo.Id,
				Success:   r.IsVul,
				Message:   r.PocInfo.Info.Name,
				LatencyMs: latency,
			}
			if cb.OnResult != nil {
				cb.OnResult(item)
			}
			// 将完整 result.Result 写入SQLite（异步队列）
			sqlite.SetResultX(r)
			gologger.Info().Msgf("SDK Runner Result: task_id=%s target=%s poc_id=%s success=%v latency=%dms", in.TaskID, item.Target, item.PocID, item.Success, item.LatencyMs)
			// 说明：当前无法立即获得插入后的 db_id；如需展示，可后续通过 AttachTaskDbID 回填
		}

		// 进度轮询：按 total = targets × pocs 计算
		total := len(in.Targets) * len(in.PocIDs)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		// 启动异步扫描
		if err := scanner.RunAsync(); err != nil {
			if cb.OnError != nil {
				cb.OnError(fmt.Sprintf("启动扫描失败: %v", err))
			}
			if cb.OnEnded != nil {
				cb.OnEnded(web.StatusFailed)
			}
			gologger.Error().Msgf("SDK Runner: RunAsync failed: %v", err)
			return err
		}
		gologger.Info().Msgf("SDK Runner: scanning started: task_id=%s total=%d", in.TaskID, total)

		// 状态与进度更新循环：监听取消与完成
		for {
			select {
			case <-ctx.Done():
				// 取消任务
				scanner.Stop()
				if cb.OnEnded != nil {
					cb.OnEnded(web.StatusCanceled)
				}
				gologger.Info().Msgf("SDK Runner: canceled via context: task_id=%s", in.TaskID)
				return nil
			case <-ticker.C:
				stats := scanner.GetStats()
				// 更新进度
				if cb.OnProgress != nil {
					cb.OnProgress(int(stats.CompletedScans), total)
				}
				gologger.Debug().Msgf("SDK Runner Progress: task_id=%s %d/%d", in.TaskID, int(stats.CompletedScans), total)
				// 完成判断
				if int(stats.CompletedScans) >= total {
					if cb.OnEnded != nil {
						cb.OnEnded(web.StatusCompleted)
					}
					gologger.Info().Msgf("SDK Runner: completed: task_id=%s", in.TaskID)
					return nil
				}
			}
		}
	})
}

// 将指定 PocIDs 的 YAML 写入临时目录，返回该目录路径
func writeTempPocsDir(pocIDs []string) (string, error) {
	dir, err := os.MkdirTemp("", "afrog-pocs-*")
	if err != nil {
		return "", err
	}
	wrote := 0
	for _, id := range pocIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		bs, err := pocsrepo.ReadYamlByID(id)
		if err != nil || len(bs) == 0 {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), bs, 0o644); err != nil {
			continue
		}
		wrote++
	}
	if wrote == 0 {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("未能写入任何 POC YAML")
	}
	return dir, nil
}