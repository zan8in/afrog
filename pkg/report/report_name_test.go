package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"github.com/zan8in/afrog/v3/pkg/result"
)

// testResult 造一份最小可用的结果，够 Append / JsonContent 渲染即可。
func testResult() *result.Result {
	return &result.Result{
		Target:  "http://example.com",
		PocInfo: &poc.Poc{Id: "report-name-test", Info: poc.Info{Name: "report-name-test", Severity: "info"}},
	}
}

// chdirToTemp 把工作目录切到临时目录，让 OutputDirectory（./reports）落到沙箱里。
func chdirToTemp(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	origin, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origin) })

	return dir
}

// readReportFiles 列出 ./reports 下的文件，用来核对落盘结果。
func readReportFiles(t *testing.T, dir string) []os.DirEntry {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join(dir, OutputDirectory))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	return entries
}

// 默认报告名是秒级时间戳（MMDD-HHMMSS）。同名候选必须逐个败给 O_EXCL，拿到互不相同的名字。
func TestReserveReportNameIsDistinctInSameSecond(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "1025-201414.html")

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		name, err := reserveReportName(candidate)
		if err != nil {
			t.Fatalf("第 %d 次抢占失败: %v", i, err)
		}
		if seen[name] {
			t.Fatalf("第 %d 次抢到已被占用的报告名 %q", i, filepath.Base(name))
		}
		seen[name] = true
	}
}

// 并发抢占时 O_EXCL 仍应原子地决出唯一赢家，不能出现两个赢家拿同一个名字。
func TestReserveReportNameIsDistinctUnderConcurrency(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "1025-201414.json")

	const workers = 16
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		names []string
		errs  []error
	)

	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			name, err := reserveReportName(candidate)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			names = append(names, name)
		}()
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		t.Errorf("并发抢占出错: %v", err)
	}

	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatalf("并发抢占出现重名报告文件 %q", filepath.Base(n))
		}
		seen[n] = true
	}
}

// 同秒内构造多个默认命名的报告并各自写入，文件名必须互不相同、内容都要留下来。
// 早先抢占后立刻删掉占位文件，保护窗口只剩几微秒，同秒内的后来者照样抢到同一个名字，
// 于是后写的把先写的截断掉，最终只剩一个文件。
func TestAutoNamedReportsAreDistinctInSameSecond(t *testing.T) {
	dir := chdirToTemp(t)

	const runs = 4
	seen := map[string]bool{}
	for i := 0; i < runs; i++ {
		r, err := NewReport("", DefaultTemplate)
		if err != nil {
			t.Fatalf("NewReport: %v", err)
		}
		r.SetResult(testResult())
		if err := r.Append(fmt.Sprintf("%d", i)); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if seen[r.ReportFile] {
			t.Fatalf("同秒内的报告共用了文件名 %q", filepath.Base(r.ReportFile))
		}
		seen[r.ReportFile] = true
	}

	entries := readReportFiles(t, dir)
	if len(entries) != runs {
		t.Fatalf("报告文件数 = %d, 期望 %d（同秒写入互相覆盖会少文件）", len(entries), runs)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("stat %s: %v", e.Name(), err)
		}
		if info.Size() == 0 {
			t.Fatalf("报告文件 %s 为空，被同秒启动的另一次扫描截断", e.Name())
		}
	}
}

// JSON 报告走的是同一套默认命名逻辑，同样要保证同秒内互不重名。
func TestAutoNamedJsonReportsAreDistinctInSameSecond(t *testing.T) {
	dir := chdirToTemp(t)

	const runs = 4
	seen := map[string]bool{}
	for i := 0; i < runs; i++ {
		jr, err := NewJsonReport("", "")
		if err != nil {
			t.Fatalf("NewJsonReport: %v", err)
		}
		jr.SetResult(testResult())
		if err := jr.Append(); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if seen[jr.ReportFile] {
			t.Fatalf("同秒内的 JSON 报告共用了文件名 %q", filepath.Base(jr.ReportFile))
		}
		seen[jr.ReportFile] = true
	}

	entries := readReportFiles(t, dir)
	if len(entries) != runs {
		t.Fatalf("JSON 报告文件数 = %d, 期望 %d", len(entries), runs)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("stat %s: %v", e.Name(), err)
		}
		if info.Size() == 0 {
			t.Fatalf("JSON 报告文件 %s 为空", e.Name())
		}
	}
}

// 构造报告实例本身不该落文件：没有命中任何结果的扫描不应在 reports 目录留下空报告。
func TestReportConstructorLeavesNoFile(t *testing.T) {
	dir := chdirToTemp(t)

	if _, err := NewReport("", DefaultTemplate); err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	if _, err := NewJsonReport("", ""); err != nil {
		t.Fatalf("NewJsonReport: %v", err)
	}

	if entries := readReportFiles(t, dir); len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("构造报告实例不应留下文件，实际有 %v", names)
	}
}
