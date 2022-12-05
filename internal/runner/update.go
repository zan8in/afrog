package runner

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
	"github.com/zan8in/afrog/pkg/config"
)

func UpdateAfrogVersionToLatest(verbose bool) error {
	var command string
	switch runtime.GOOS {
	case "windows":
		command = "afrog.exe"
	default:
		command = "afrog"
	}
	m := &update.Manager{
		Command: command,
		Store: &githubUpdateStore.Store{
			Owner:   "zan8in",
			Repo:    "afrog",
			Version: config.Version,
		},
	}
	releases, err := m.LatestReleases()
	if err != nil {
		return errors.Wrap(err, "could not fetch latest release")
	}
	if len(releases) == 0 {
		fmt.Println("No new updates found for afrog engine!")
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
	//https: //gitee.com/zanbin/afrog/releases/download/v2.0.1/afrog_windows_amd64.zip
	final.URL = strings.Replace(final.URL, "github.com/zan8in", "gitee.com/zanbin", -1)
	tarball, err := final.DownloadProxy(progress.Reader)
	if err != nil {
		return errors.Wrap(err, "could not download latest release")
	}
	if err := m.Install(tarball); err != nil {
		return errors.Wrap(err, "could not install latest release")
	}
	fmt.Printf("Successfully updated to afrog %s\n", latest.Version)

	return nil
}
