package config

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/zan8in/gologger"
	"github.com/zan8in/goupdate"
	"github.com/zan8in/goupdate/progress"
	githubstore "github.com/zan8in/goupdate/stores/github"
)

func UpdateAfrogEngine() error {
	return updateEngine()
}

func updateEngine() error {
	var command string
	switch runtime.GOOS {
	case "windows":
		command = "afrog.exe"
	default:
		command = "afrog"
	}

	m := goupdate.Manager{
		Command: command,
		Store: &githubstore.Store{
			Owner:   "zan8in",
			Repo:    "afrog",
			Version: Version,
		},
	}

	releases, err := m.LatestReleases()
	if err != nil {
		return errors.Wrap(err, "could not fetch latest release")
	}
	if len(releases) == 0 {
		gologger.Info().Msg("afrog is already up-to-date and doesn't require an update.")
		return nil
	}

	latest := releases[0]

	var currentOS string
	switch runtime.GOOS {
	case "darwin":
		currentOS = "macOS"
	default:
		currentOS = runtime.GOOS
	}
	final := latest.FindZip(currentOS, runtime.GOARCH)
	if final == nil {
		return fmt.Errorf("no compatible binary found for %s/%s", currentOS, runtime.GOARCH)
	}

	//https://gitee.com/zanbin/afrog/releases/download/v2.0.1/afrog_windows_amd64.zip
	final.URL = strings.Replace(final.URL, "github.com/zan8in", "gitee.com/zanbin", -1)

	tarball, err := final.DownloadProxy(progress.Reader)
	if err != nil {
		return errors.Wrap(err, "could not download latest release")
	}

	if err := m.Install(tarball); err != nil {
		return errors.Wrap(err, "could not install latest release")
	}

	gologger.Info().Msgf("Successfully updated to afrog %s\n", latest.Version)

	return nil
}
