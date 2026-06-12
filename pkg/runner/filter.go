package runner

import (
	"strings"

	"github.com/zan8in/afrog/v3/pkg/poc"
)

func shouldSkipRequires(target string, p poc.Poc, keyForTarget func(string) string, fingerTagsByKey map[string]map[string]struct{}, testMode bool) bool {
	if testMode {
		return false
	}
	if len(p.Info.Requires) == 0 {
		return false
	}
	reqSet := make(map[string]struct{}, len(p.Info.Requires))
	for _, r := range p.Info.Requires {
		rr := strings.ToLower(strings.TrimSpace(r))
		if rr == "" {
			continue
		}
		reqSet[rr] = struct{}{}
	}
	if len(reqSet) == 0 {
		return false
	}

	mode := strings.ToLower(strings.TrimSpace(p.Info.RequiresMode))
	if mode == "" {
		mode = "strict"
	}
	if mode != "strict" && mode != "opportunistic" {
		mode = "strict"
	}

	if len(fingerTagsByKey) == 0 {
		return mode == "strict"
	}

	key := ""
	if keyForTarget != nil {
		key = keyForTarget(target)
	}
	if key == "" {
		return mode == "strict"
	}

	tts := fingerTagsByKey[key]
	if len(tts) == 0 {
		return mode == "strict"
	}
	for r := range reqSet {
		if _, ok := tts[r]; ok {
			return false
		}
	}
	return true
}

func shouldSkipFingerprintFilteredByMode(mode string, globalFingerTags map[string]struct{}, targetTags map[string]struct{}, pocTags map[string]struct{}) bool {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "strict"
	}
	if mode != "strict" && mode != "opportunistic" {
		mode = "strict"
	}
	if len(globalFingerTags) == 0 || len(pocTags) == 0 {
		return false
	}
	appSpecific := false
	for t := range pocTags {
		if _, ok := globalFingerTags[t]; ok {
			appSpecific = true
			break
		}
	}
	if !appSpecific {
		return false
	}
	if len(targetTags) == 0 {
		return mode == "strict"
	}
	for t := range pocTags {
		if _, ok := targetTags[t]; ok {
			return false
		}
	}
	return true
}
