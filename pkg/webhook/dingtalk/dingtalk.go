package dingtalk

import (
	"errors"
	"fmt"
	"strings"

	ding "github.com/blinkbean/dingtalk"
	timeutil "github.com/zan8in/pins/time"
)

type Dingtalk struct {
	Ding      *ding.DingTalk
	Tokens    []string // Tokens 单个机器人有单位时间内消息条数的限制，如果有需要可以初始化多个token，发消息时随机发给其中一个机器人。
	AtMobiles []string // 可选参数 @指定群成员
	AtAll     bool     // 可选参数 @所有人
	Range     string   // 漏洞通知范围，默认 high,critical
}

func New(tokens, atMobiles []string, rang string, atAll bool) (*Dingtalk, error) {
	if len(tokens) == 0 {
		return nil, errors.New("tokens can not be empty")
	}
	return &Dingtalk{
		Ding:      ding.InitDingTalk(tokens, "."),
		Tokens:    tokens,
		AtMobiles: atMobiles,
		AtAll:     atAll,
		Range:     rang,
	}, nil
}

func (d *Dingtalk) SendMarkDownMessageBySlice(title string, mkcontent []string) error {
	if mkcontent == nil {
		return nil
	}
	if d.AtAll {
		return d.Ding.SendMarkDownMessageBySlice(title, mkcontent, ding.WithAtAll())
	}
	if !d.IsAtMobilesEmpty() {
		return d.Ding.SendMarkDownMessageBySlice(title, mkcontent, ding.WithAtMobiles(d.AtMobiles))
	}
	return d.Ding.SendMarkDownMessageBySlice(title, mkcontent)
}

func (d *Dingtalk) MarkdownText(id, severity, url string) []string {
	if !strings.Contains(d.Range, strings.ToLower(severity)) {
		return nil
	}
	return []string{
		fmt.Sprintf("##### %s <font color=RED><b>%s</b></font>", id, d.Severity(severity)),
		"---",
		fmt.Sprintf("%s<br/>", url),
		fmt.Sprintf("<font color=GRAY>%s\tfr.afrog</font>", timeutil.Format(timeutil.FormatShortDateTime)),
	}
}

func (d *Dingtalk) Severity(s string) string {
	r := ""
	if strings.TrimSpace(s) == "high" {
		r = "RED"
	} else if strings.TrimSpace(s) == "critical" {
		r = "#b454ff"
	} else if strings.TrimSpace(s) == "medium" {
		r = "#ff9900"
	} else {
		r = "blue"
	}
	return fmt.Sprintf("<font color='%s'><b>%s</b></font>", r, s)
}

func IsTokensEmpty(tokens []string) bool {
	if len(tokens) == 0 {
		return true
	}
	for _, token := range tokens {
		if len(token) > 0 {
			return false
		}
	}
	return true
}

func (d *Dingtalk) IsAtMobilesEmpty() bool {
	if len(d.AtMobiles) == 0 {
		return true
	}
	for _, mobile := range d.AtMobiles {
		if len(mobile) > 0 {
			return false
		}
	}
	return true
}
