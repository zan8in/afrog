package drafter

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// Command 实现 `afrog poc <sub>`：候选 PoC 的人工终审入口。
//
// 这是流水线里唯一「人」的一步：模型可以提议、沙箱可以实跑，但把候选写进用户
// PoC 目录（pocs-my）必须由人显式批准。子命令：pending / list / show / approve / reject。
func Command(args []string) error {
	if err := sqlite.NewWebSqliteDB(); err != nil {
		return err
	}
	defer sqlite.CloseX()

	sub := "pending"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "pending":
		return cmdList(args, sqlite.PocDraftPending)
	case "list":
		return cmdList(args, "")
	case "show":
		return cmdShow(args)
	case "approve":
		return cmdApprove(args)
	case "reject":
		return cmdReject(args)
	case "stats":
		return cmdStats(args)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `afrog poc —— 候选 PoC 人工终审

用法:
  afrog poc pending [--json]              列出待审候选（默认）
  afrog poc list [--status s] [--json]    列出候选，status: pending|approved|rejected
  afrog poc show <id> [--json]            查看一条候选详情
  afrog poc approve <id>                  批准并入库到 ~/.config/afrog/pocs-my
  afrog poc reject <id> [-note "..."]     驳回候选（保留草稿与原因）
  afrog poc stats [--json]                自动入库率等流水线指标
`)
}

func cmdList(args []string, defaultStatus string) error {
	fs := flag.NewFlagSet("afrog poc list", flag.ContinueOnError)
	status := fs.String("status", defaultStatus, "过滤状态：pending|approved|rejected；留空为全部")
	asJSON := fs.Bool("json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		return err
	}

	items, err := List(*status)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(items)
	}
	if len(items) == 0 {
		fmt.Println("没有符合条件的候选。")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATUS\tSEVERITY\tCAPABILITY\tTARGET\tUPDATED")
	for _, it := range items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			it.ID, it.Status, orDash(it.Severity), orDash(it.Capability), orDash(it.Target), it.Updated)
	}
	return w.Flush()
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("afrog poc show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := strings.TrimSpace(fs.Arg(0))
	if id == "" {
		return fmt.Errorf("id is required")
	}
	rec, err := Show(id)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("poc draft %q not found", id)
	}
	if *asJSON {
		return printJSON(rec)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "id\t%s\n", rec.ID)
	fmt.Fprintf(w, "status\t%s\n", rec.Status)
	fmt.Fprintf(w, "name\t%s\n", orDash(rec.Name))
	fmt.Fprintf(w, "severity\t%s\n", orDash(rec.Severity))
	fmt.Fprintf(w, "capability\t%s\n", orDash(rec.Capability))
	fmt.Fprintf(w, "requests\t%d\n", rec.Requests)
	fmt.Fprintf(w, "draft\t%s\n", orDash(rec.Path))
	fmt.Fprintf(w, "target\t%s\n", orDash(rec.Target))
	fmt.Fprintf(w, "evidence_id\t%s\n", orDash(rec.EvidenceID))
	fmt.Fprintf(w, "evidence_digest\t%s\n", orDash(rec.EvidenceDigest))
	fmt.Fprintf(w, "note\t%s\n", orDash(rec.Note))
	fmt.Fprintf(w, "created\t%s\n", rec.Created)
	fmt.Fprintf(w, "updated\t%s\n", rec.Updated)
	return w.Flush()
}

func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("afrog poc approve", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := strings.TrimSpace(fs.Arg(0))
	if id == "" {
		return fmt.Errorf("id is required")
	}
	res, err := Approve(id)
	if err != nil {
		return err
	}
	fmt.Printf("已入库: %s\n", res.Path)
	return nil
}

func cmdReject(args []string) error {
	fs := flag.NewFlagSet("afrog poc reject", flag.ContinueOnError)
	note := fs.String("note", "", "驳回原因（可选）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := strings.TrimSpace(fs.Arg(0))
	if id == "" {
		return fmt.Errorf("id is required")
	}
	if err := Reject(id, *note); err != nil {
		return err
	}
	fmt.Printf("已驳回: %s\n", id)
	return nil
}

// cmdStats 打印 Drafter 流水线的量化指标：候选产出后有多少真的入库了。
func cmdStats(args []string) error {
	fs := flag.NewFlagSet("afrog poc stats", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := GetStats()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(st)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "total\t%d\n", st.Total)
	fmt.Fprintf(w, "pending\t%d\n", st.Pending)
	fmt.Fprintf(w, "approved\t%d\n", st.Approved)
	fmt.Fprintf(w, "rejected\t%d\n", st.Rejected)
	fmt.Fprintf(w, "reviews\t%d\n", st.Reviews)
	fmt.Fprintf(w, "ingest_rate\t%s\n", formatRate(st.IngestRate, st.Reviewed))
	printBuckets(w, "by_severity", st.BySeverity)
	printBuckets(w, "by_capability", st.ByCapability)
	return w.Flush()
}

func printBuckets(w *tabwriter.Writer, title string, buckets []Bucket) {
	if len(buckets) == 0 {
		return
	}
	fmt.Fprintf(w, "%s\tapproved/total\tingest_rate\n", title)
	for _, b := range buckets {
		fmt.Fprintf(w, "\t%s\t%d/%d\t%s\n", b.Name, b.Approved, b.Total, formatRate(b.IngestRate, b.Approved+b.Rejected))
	}
}

// formatRate 渲染入库率；无决议时显式写 n/a，避免把「没人审」误读成 0%。
func formatRate(rate float64, reviewed int) string {
	if reviewed == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", rate*100)
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
