// Command docscheck 校验 docs/ 的内容质量，是文档 CI 的入口：
//
//  1. 中英文镜像一致性：docs/zh 与 docs/en 的相对文件路径必须一一对应；
//  2. 站内链接有效性：正文里的相对链接必须指向真实存在的文件。
//
// 刻意只依赖标准库：这是一道轻量护栏，不值得为它引入 Markdown/链接解析依赖。
// 用法：在仓库根目录执行 `go run ./cmd/docscheck`。
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// markdownLinkRe 匹配行内链接的目标部分 `](target)`。标题/锚点由后续逻辑剥离。
var markdownLinkRe = regexp.MustCompile(`\]\(([^)]+)\)`)

func main() {
	docsRoot := flag.String("docs", "docs", "文档根目录")
	flag.Parse()

	problems, err := run(*docsRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "docscheck: "+err.Error())
		os.Exit(1)
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "- "+p)
		}
		fmt.Fprintf(os.Stderr, "docscheck: 发现 %d 个问题\n", len(problems))
		os.Exit(1)
	}
	fmt.Println("docscheck: 通过（中英文目录一致、站内链接有效）")
}

func run(root string) ([]string, error) {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("找不到文档目录 %q", root)
	}

	problems := make([]string, 0, 16)

	zh, err := listMarkdown(root, "zh")
	if err != nil {
		return nil, err
	}
	en, err := listMarkdown(root, "en")
	if err != nil {
		return nil, err
	}
	problems = append(problems, compareMirrors("zh", zh, "en", en)...)

	links, err := checkLinks(root)
	if err != nil {
		return nil, err
	}
	problems = append(problems, links...)

	return problems, nil
}

// listMarkdown 返回 lang 子目录下全部 .md 的相对路径（以 / 分隔，已排序）。
func listMarkdown(root, lang string) ([]string, error) {
	base := filepath.Join(root, lang)
	out := make([]string, 0, 64)
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		rel, relErr := filepath.Rel(base, path)
		if relErr != nil {
			return relErr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历 %s: %w", base, err)
	}
	sort.Strings(out)
	return out, nil
}

// compareMirrors 比较两份文件清单，指出双方各自缺失的镜像文件。
func compareMirrors(langA string, a []string, langB string, b []string) []string {
	problems := make([]string, 0, 8)
	problems = append(problems, missing(langB, b, langA, a)...)
	problems = append(problems, missing(langA, a, langB, b)...)
	return problems
}

func missing(langMissing string, listMissing []string, langFrom string, listFrom []string) []string {
	have := make(map[string]struct{}, len(listMissing))
	for _, p := range listMissing {
		have[p] = struct{}{}
	}
	problems := make([]string, 0, 4)
	for _, p := range listFrom {
		if _, ok := have[p]; ok {
			continue
		}
		problems = append(problems, fmt.Sprintf("中英文不一致：%s/%s 存在，但 %s/%s 缺失", langFrom, p, langMissing, p))
	}
	return problems
}

// checkLinks 扫描 root 下所有 Markdown，校验站内相对链接的目标文件是否存在。
func checkLinks(root string) ([]string, error) {
	problems := make([]string, 0, 16)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		display := filepath.ToSlash(rel)
		for _, target := range extractLinkTargets(string(data)) {
			if skipLinkTarget(target) {
				continue
			}
			// 只校验文件本身：`foo.md#section` 的锚点部分由站点渲染时处理。
			linkPath := linkFilePath(target)
			if linkPath == "" {
				continue
			}
			resolved := filepath.Join(filepath.Dir(path), filepath.FromSlash(linkPath))
			if _, statErr := os.Stat(resolved); statErr != nil {
				problems = append(problems, fmt.Sprintf("链接失效：%s 里的 %q 指向不存在的文件", display, target))
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("扫描链接: %w", err)
	}
	sort.Strings(problems)
	return problems, nil
}

// extractLinkTargets 取出正文里的行内链接目标。代码块中的示例链接不算数——
// 文档里常拿 `](...)` 演示写法，不该被当成真链接校验。
func extractLinkTargets(content string) []string {
	out := make([]string, 0, 32)
	for _, line := range stripFencedCode(content) {
		for _, m := range markdownLinkRe.FindAllStringSubmatch(line, -1) {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return out
}

// stripFencedCode 去掉 ``` 围栏代码块的整段内容，围栏行自身也一并去掉。
func stripFencedCode(content string) []string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	inFence := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		out = append(out, line)
	}
	return out
}

// skipLinkTarget 判断链接目标是否属于「无需校验」的类别：外链、纯锚点、
// 站内绝对路径（拼接规则由站点决定，本地无从解析）。
func skipLinkTarget(target string) bool {
	t := strings.TrimSpace(target)
	t = strings.Trim(t, "<>")
	if t == "" {
		return true
	}
	lower := strings.ToLower(t)
	for _, prefix := range []string{"http://", "https://", "mailto:", "tel:", "//"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/")
}

// linkFilePath 从链接目标里取出「文件路径」部分，剥离 #fragment 与 ?query。
// 返回空串表示这个链接没有指向任何文件。
func linkFilePath(target string) string {
	t := strings.TrimSpace(target)
	t = strings.Trim(t, "<>")
	t = strings.SplitN(t, "#", 2)[0]
	t = strings.SplitN(t, "?", 2)[0]
	return strings.TrimSpace(t)
}
