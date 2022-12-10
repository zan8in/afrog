package upgrade

import (
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/cavaliergopher/grab/v3"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

type Upgrade struct {
	HomeDir             string
	CurrVersion         string
	RemoteVersion       string
	LastestVersion      string
	LastestAfrogVersion string
	IsUpdatePocs        bool
}

const (
	// upHost = "http://binbin.run/afrog-release"
	upHost          = "https://gitee.com/zanbin/afrog/raw/main/pocs/v"
	upPathName      = "/afrog-pocs"
	upPath          = "/afrog-pocs.zip"
	upRemoteVersion = "/version"
	afrogVersion    = "/afrog.version"
)

func New(updatePoc bool) *Upgrade {
	homeDir, _ := os.UserHomeDir()
	return &Upgrade{HomeDir: homeDir, IsUpdatePocs: updatePoc}
}

func (u *Upgrade) CheckUpgrade() (bool, error) {
	curVersion, err := poc.GetPocVersionNumber()
	u.CurrVersion = curVersion
	if err != nil {
		return false, errors.New("failed to get local version number")
	}

	resp, err := http.Get(upHost + upRemoteVersion)
	if err != nil {
		return false, errors.New("failed to get remote version number")
	}
	defer resp.Body.Close()

	remoteVersion, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, errors.New("failed to get remote version number")
	}

	u.RemoteVersion = strings.TrimSpace(string(remoteVersion))

	u.LastestAfrogVersion, _ = getAfrogVersion()

	return utils.Compare(strings.TrimSpace(string(remoteVersion)), ">", curVersion), nil
}

func getAfrogVersion() (string, error) {
	resp, err := http.Get(upHost + afrogVersion)
	if err != nil {
		return "", errors.New("failed to get remote version number")
	}
	defer resp.Body.Close()

	afrogversion, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("failed to get remote version number")
	}
	return strings.TrimSpace(string(afrogversion)), nil
}

func (u *Upgrade) UpgradeAfrogPocs() {
	isUp, err := u.CheckUpgrade()
	if err != nil {
		if u.IsUpdatePocs {
			gologger.Fatal().Msgf("The afrog-pocs update failed, %s\n", err.Error())
		}
	}
	if !isUp {
		if u.IsUpdatePocs {
			gologger.Info().Msgf("No new updates found for afrog-pocs!")
		}
		return
	}
	if isUp {
		u.LastestVersion = u.RemoteVersion
		if u.IsUpdatePocs {
			gologger.Info().Msgf("Downloading latest afrog-pocs release...")
			u.Download()
		}
	}
}

func (u *Upgrade) Download() {
	resp, err := grab.Get(u.HomeDir, upHost+upPath)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
		return
	}
	os.RemoveAll(u.HomeDir + upPathName)
	utils.RandSleep(1000)

	u.Unzip(resp.Filename)

	utils.RandSleep(1000)

	os.Remove(resp.Filename)
}

func (u *Upgrade) Unzip(src string) {
	uz := utils.NewUnzip()

	_, err := uz.Extract(src, u.HomeDir)
	if err != nil {
		gologger.Fatal().Msgf("The afrog-pocs upzip failed, %s\n", err.Error())
	}

	gologger.Info().Msgf("Successfully updated to afrog-pocs %s\n", strings.ReplaceAll(u.HomeDir+upPathName, "\\", "/"))
}
