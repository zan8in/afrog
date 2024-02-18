package config

import (
	"github.com/zan8in/gologger"
	"github.com/zan8in/goupdate"
	"github.com/zan8in/goupdate/stores/gitee"
)

func updateEngine() error {
	owner := "zanbin"
	repo := "afrog"
	version := Version

	if result, err := gitee.Update(owner, repo, version); err != nil {
		return err
	} else {
		if result.Status == 2 {
			gologger.Info().Msgf("%s %s", repo, goupdate.LatestVersionTips)
		} else {
			gologger.Info().Msgf("Successfully updated to %s %s\n", repo, result.LatestVersion)
		}
	}
	return nil
}
