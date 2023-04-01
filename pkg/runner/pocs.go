package runner

import (
	"sync/atomic"

	"github.com/pkg/errors"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pocs"
	"github.com/zan8in/gologger"
)

func (r *Runner) PreprocessPocs() error {
	// init pocs
	allPocsEmbedYamlSlice := []string{}
	if len(r.options.PocsFilePath) > 0 {
		r.options.PocsDirectory.Set(r.options.PocsFilePath)
	} else {
		// init default afrog-pocs
		if allDefaultPocsYamlSlice, err := pocs.GetPocs(); err == nil {
			allPocsEmbedYamlSlice = append(allPocsEmbedYamlSlice, allDefaultPocsYamlSlice...)
		}
		// init ~/afrog-pocs
		pocsDir, _ := poc.InitPocHomeDirectory()
		if len(pocsDir) > 0 {
			r.options.PocsDirectory.Set(pocsDir)
		}
	}
	allPocsYamlSlice := r.catalog.GetPocsPath(r.options.PocsDirectory)

	if len(allPocsYamlSlice) == 0 && len(allPocsEmbedYamlSlice) == 0 {
		return errors.New("afrog-pocs not found")
	}

	defer close(r.ChanPocs)

	for _, pocYaml := range allPocsYamlSlice {
		if v, err := poc.ReadPocs(pocYaml); err == nil {
			if len(r.options.Search) > 0 && r.options.SetSearchKeyword() && r.options.CheckPocKeywords(v.Id, v.Info.Name) {
				r.ChanPocs <- v
				atomic.AddUint32(&r.options.PocsTotal, 1)
			} else if len(r.options.Severity) > 0 && r.options.SetSeverityKeyword() && r.options.CheckPocSeverityKeywords(v.Info.Severity) {
				r.ChanPocs <- v
				atomic.AddUint32(&r.options.PocsTotal, 1)
			} else if len(r.options.Search) == 0 && len(r.options.Severity) == 0 {
				r.ChanPocs <- v
				atomic.AddUint32(&r.options.PocsTotal, 1)
			}
		} else {
			gologger.Error().Msgf("%s is not a valid poc YAML file", pocYaml)
		}
	}

	for _, pocEmbedYaml := range allPocsEmbedYamlSlice {
		if v, err := pocs.ReadPocs(pocEmbedYaml); err == nil {
			if len(r.options.Search) > 0 && r.options.SetSearchKeyword() && r.options.CheckPocKeywords(v.Id, v.Info.Name) {
				r.ChanPocs <- v
				atomic.AddUint32(&r.options.PocsTotal, 1)
			} else if len(r.options.Severity) > 0 && r.options.SetSeverityKeyword() && r.options.CheckPocSeverityKeywords(v.Info.Severity) {
				r.ChanPocs <- v
				atomic.AddUint32(&r.options.PocsTotal, 1)
			} else if len(r.options.Search) == 0 && len(r.options.Severity) == 0 {
				r.ChanPocs <- v
				atomic.AddUint32(&r.options.PocsTotal, 1)
			}
		} else {
			gologger.Error().Msgf("%s is not a valid poc YAML file", pocEmbedYaml)
		}
	}

	return nil
}
