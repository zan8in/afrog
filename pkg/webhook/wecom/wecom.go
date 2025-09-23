package wecom

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"

	wxworkbot "github.com/vimsucks/wxwork-bot-go"
	"github.com/zan8in/afrog/v3/pkg/result"
	timeutil "github.com/zan8in/pins/time"
)

type Wecom struct {
	Tokens    []string
	Range     string
	AtMobiles []string
	AtAll     bool
	Markdown  bool
}

func New(tokens, atMobiles []string, rang string, atAll bool, markdown bool) (*Wecom, error) {
	if len(tokens) == 0 {
		return nil, errors.New("tokens can not be empty")
	}
	return &Wecom{
		Tokens:    tokens,
		AtMobiles: atMobiles,
		AtAll:     atAll,
		Range:     rang,
		Markdown:  markdown,
	}, nil
}
func (w *Wecom) SendVulMessage(result *result.Result, markdown bool) error {
	if result == nil {
		return nil
	}
	content := []string{}
	if w.AtAll {
		w.AtMobiles = append(w.AtMobiles, "@all")
	}
	if !markdown {
		content = w.makeText(result.PocInfo.Id, result.PocInfo.Info.Severity, result.FullTarget)
	} else {
		content = w.markdownText(result.PocInfo.Id, result.PocInfo.Info.Severity, result.FullTarget)
	}
	if content == nil {
		return nil
	}
	if w.Markdown {
		content = append(content, "<@all>")
	}
	return w.sendMessage(content, markdown)
}
func (w *Wecom) sendMessage(content []string, markdown bool) error {
	bot := wxworkbot.New(w.Tokens[rand.Intn(len(w.Tokens))])
	if !markdown {
		text := wxworkbot.Text{
			Content:             strings.Join(content, "\n"),
			MentionedMobileList: w.AtMobiles,
		}
		err := bot.Send(text)
		if err != nil {
			return err
		}
	} else {
		markdownText := wxworkbot.Markdown{Content: strings.Join(content, "\n")}
		err := bot.Send(markdownText)
		if err != nil {
			return err
		}
	}
	return nil
}
func (w *Wecom) markdownText(id, severity, url string) []string {
	if !strings.Contains(w.Range, strings.ToLower(severity)) {
		return nil
	}
	return []string{
		fmt.Sprintf("##### %s %s", id, w.severity(severity)),
		"---",
		fmt.Sprintf("%s", url),
		fmt.Sprintf("<font color=GRAY>%s\tfr.afrog</font>", timeutil.Format(timeutil.FormatShortDateTime)),
	}
}
func (w *Wecom) makeText(id, severity, url string) []string {
	if !strings.Contains(w.Range, strings.ToLower(severity)) {
		return nil
	}
	return []string{
		fmt.Sprintf("Time: %s", timeutil.Format(timeutil.FormatShortDateTime)),
		fmt.Sprintf("Vuln Name: %s\nVunln Level:%s", id, severity),
		fmt.Sprintf("Target: %s", url),
	}
}
func (w *Wecom) severity(s string) string {
	r := "warning"
	if strings.TrimSpace(s) == "info" {
		r = "info"
	}
	return fmt.Sprintf("<font color='%s'>%s</font>", r, s)
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
func (w *Wecom) isAtMobilesEmpty() bool {
	if len(w.AtMobiles) == 0 {
		return true
	}
	for _, mobile := range w.AtMobiles {
		if len(mobile) > 0 {
			return false
		}
	}
	return true
}
