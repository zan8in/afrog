package upgrade

import (
	"errors"
	"fmt"
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
	upHost          = "https://gitee.com/zanbin/afrog/raw/main/pocs/v"
	upPathName      = "/afrog-pocs"
	upPath          = "/afrog-pocs.zip"
	upRemoteVersion = "/version"
	afrogVersion    = "/afrog.version"
)

func NewUpgrade(updatePoc bool) (*Upgrade, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	u := &Upgrade{HomeDir: homeDir, IsUpdatePocs: updatePoc}

	curVersion, err := poc.GetPocVersionNumber()
	if err != nil {
		return u, errors.New("failed to retrieve the version information of afrog-poc locally")
	}
	u.CurrVersion = curVersion

	return u, err
}

func (u *Upgrade) CheckUpgrade() (bool, error) {

	resp, err := http.Get(upHost + upRemoteVersion)
	if err != nil {
		return false, errors.New("failed to retrieve the version information of afrog-poc remotely")
	}
	defer resp.Body.Close()

	remoteVersion, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, errors.New("failed to retrieve the version information of afrog-poc remotely")
	}

	u.RemoteVersion = strings.TrimSpace(string(remoteVersion))

	u.LastestAfrogVersion, err = getAfrogVersion()
	if err != nil {
		return false, err
	}

	return utils.Compare(strings.TrimSpace(string(remoteVersion)), ">", u.CurrVersion), nil
}

func getAfrogVersion() (string, error) {
	resp, err := http.Get(upHost + afrogVersion)
	if err != nil {
		return "", errors.New("failed to retrieve the version information of afrog remotely")
	}
	defer resp.Body.Close()

	afrogversion, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("failed to retrieve the version information of afrog remotely")
	}
	return strings.TrimSpace(string(afrogversion)), nil
}

func (u *Upgrade) UpgradePocs() (string, error) {
	isUp, err := u.CheckUpgrade()
	if err != nil {
		if u.IsUpdatePocs {
			return "", fmt.Errorf("afrog-poc update failed. %s", err.Error())
		}
	}
	if !isUp {
		if u.IsUpdatePocs {
			return "The current version of afrog-pocs is already up-to-date.", nil
		}
	}
	if isUp {
		if u.IsUpdatePocs {
			gologger.Print().Msg("Downloading the latest version of afrog-pocs...")
			return "", u.Download()
		}
	}
	return "", err
}

func (u *Upgrade) Download() error {
	resp, err := grab.Get(u.HomeDir, upHost+upPath)
	if err != nil {
		return fmt.Errorf("%s", err.Error())
	}

	if err = os.RemoveAll(u.HomeDir + upPathName); err != nil {
		return err
	}

	utils.RandSleep(1000)

	u.Unzip(resp.Filename)

	utils.RandSleep(1000)

	u.LastestVersion = u.RemoteVersion

	return os.Remove(resp.Filename)
}

func (u *Upgrade) Unzip(src string) error {
	uz := utils.NewUnzip()

	if _, err := uz.Extract(src, u.HomeDir); err != nil {
		return fmt.Errorf("afrog-poc decompression failed. %s", err.Error())
	}

	if len(u.RemoteVersion) > 0 {
		u.CurrVersion = u.RemoteVersion
	}
	gologger.Print().Msgf("afrog-poc has been updated successfully and the path is: %s\n", strings.ReplaceAll(u.HomeDir+upPathName, "\\", "/"))

	return nil
}
