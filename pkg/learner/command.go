package learner

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/zan8in/afrog/v3/pkg/db/sqlite"
)

// Command 实现 `afrog learn <sub>`：Learner 调优建议的人工审阅入口。
//
// 与 `afrog poc` 对称：模型可以提建议，但「采纳」只是记录人的决策——afrog 不会
// 自动把 diff 应用到规则/阈值上；真正的变更由人走正常代码流程完成。
// 子命令：list / show / accept / reject。
func Command(args []string) error {
	if err := sqlite.NewWebSqliteDB(); err != nil {
		return err
	}
	defer sqlite.CloseX()

	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "list", "pending":
		return cmdList(args)
	case "show":
		return cmdShow(args)
	case "accept":
		return cmdAccept(args)
	case "reject":
		return cmdReject(args)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `afrog learn —— 规则/阈值调优建议的人工审阅

用法:
  afrog learn list [--status s] [--json]   列出建议，status: pending|accepted|rejected（默认 pending）
  afrog learn show <id> [--json]           查看一条建议（含 diff）
  afrog learn accept <id> [-note "..."]    采纳建议（仅记录决策，不自动应用 diff）
  afrog learn reject <id> [-note "..."]    驳回建议
`)
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("afrog learn list", flag.ContinueOnError)
	status := fs.String("status", sqlite.LearnSuggestionPending, "过滤状态：pending|accepted|rejected；留空为全部")
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
		fmt.Println("没有符合条件的建议。")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATUS\tKIND\tSUMMARY\tUPDATED")
	for _, it := range items {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", it.ID, it.Status, orDash(it.Kind), it.Summary, it.Updated)
	}
	return w.Flush()
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("afrog learn show", flag.ContinueOnError)
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
		return fmt.Errorf("learn suggestion %q not found", id)
	}
	if *asJSON {
		return printJSON(rec)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "id\t%s\n", rec.ID)
	fmt.Fprintf(w, "status\t%s\n", rec.Status)
	fmt.Fprintf(w, "kind\t%s\n", orDash(rec.Kind))
	fmt.Fprintf(w, "summary\t%s\n", rec.Summary)
	fmt.Fprintf(w, "source\t%s\n", orDash(rec.Source))
	fmt.Fprintf(w, "actor\t%s\n", orDash(rec.Actor))
	fmt.Fprintf(w, "note\t%s\n", orDash(rec.Note))
	fmt.Fprintf(w, "created\t%s\n", rec.Created)
	fmt.Fprintf(w, "updated\t%s\n", rec.Updated)
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Printf("\n--- diff ---\n%s\n", rec.Diff)
	return nil
}

func cmdAccept(args []string) error {
	fs := flag.NewFlagSet("afrog learn accept", flag.ContinueOnError)
	note := fs.String("note", "", "采纳备注（可选）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := strings.TrimSpace(fs.Arg(0))
	if id == "" {
		return fmt.Errorf("id is required")
	}
	if err := Accept(id, *note); err != nil {
		return err
	}
	fmt.Printf("已采纳（未自动应用，请按需手动变更）: %s\n", id)
	return nil
}

func cmdReject(args []string) error {
	fs := flag.NewFlagSet("afrog learn reject", flag.ContinueOnError)
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
