package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile 在测试临时目录里落一个文件，自动补建父目录。
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// 镜像一致 + 链接有效的文档树不应报任何问题。
func TestRunCleanTree(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "zh", "index.md"), "## 首页\n\n见 [安装](./user-guide/02-install.md)。\n")
	writeFile(t, filepath.Join(root, "zh", "user-guide", "02-install.md"), "## 安装\n")
	writeFile(t, filepath.Join(root, "en", "index.md"), "## Home\n\nSee [Install](./user-guide/02-install.md).\n")
	writeFile(t, filepath.Join(root, "en", "user-guide", "02-install.md"), "## Install\n")

	problems, err := run(root)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("干净的文档树不应有问题，实际：%v", problems)
	}
}

// 中英文镜像缺失要被指出。
func TestRunDetectsMirrorGap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "zh", "index.md"), "# 首页\n")
	writeFile(t, filepath.Join(root, "zh", "poc", "01-quickstart.md"), "# 快速开始\n")
	writeFile(t, filepath.Join(root, "en", "index.md"), "# Home\n")

	problems, err := run(root)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !hasProblem(problems, "en/poc/01-quickstart.md 缺失") {
		t.Fatalf("应报告英文镜像缺失，实际：%v", problems)
	}
}

// 指向不存在文件的相对链接要被指出。
func TestRunDetectsBrokenLink(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "zh", "index.md"), "见 [安装](./user-guide/02-install.md)。\n")
	writeFile(t, filepath.Join(root, "en", "index.md"), "# Home\n")

	problems, err := run(root)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !hasProblem(problems, "链接失效") {
		t.Fatalf("应报告链接失效，实际：%v", problems)
	}
}

// 外链、纯锚点、带 fragment 的站内链接都不该误报。
func TestLinkTargetsFiltering(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "README.md"), "# Docs\n")
	writeFile(t, filepath.Join(root, "zh", "index.md"), strings.Join([]string{
		"[外链](https://example.com/a.md)",
		"[锚点](#section)",
		"[带片段](./other.md#part)",
		"[相对上级](../README.md)",
	}, "\n")+"\n")
	writeFile(t, filepath.Join(root, "zh", "other.md"), "# Other\n")
	writeFile(t, filepath.Join(root, "en", "index.md"), "# Home\n")
	writeFile(t, filepath.Join(root, "en", "other.md"), "# Other\n")

	problems, err := run(root)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("合法链接不该被误报：%v", problems)
	}
}

// 代码块里的示例链接不该被当成真链接校验。
func TestExtractLinkTargetsSkipsFencedCode(t *testing.T) {
	content := "真实： [a](./a.md)\n\n```markdown\n示例：[不存在](./missing.md)\n```\n\n尾部： [b](./b.md)\n"
	got := extractLinkTargets(content)
	want := []string{"./a.md", "./b.md"}
	if len(got) != len(want) {
		t.Fatalf("提取结果 = %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("提取结果 = %v，期望 %v", got, want)
		}
	}
}

func TestLinkFilePathStripsFragmentAndQuery(t *testing.T) {
	cases := map[string]string{
		"./a.md#section": "./a.md",
		"./a.md?raw=1":   "./a.md",
		"#anchor":        "",
		"<./a.md>":       "./a.md",
	}
	for in, want := range cases {
		if got := linkFilePath(in); got != want {
			t.Fatalf("linkFilePath(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func hasProblem(problems []string, substr string) bool {
	for _, p := range problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}
