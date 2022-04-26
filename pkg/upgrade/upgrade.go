package upgrade

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/cavaliergopher/grab/v3"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/poc"
	"github.com/zan8in/afrog/pkg/utils"
)

type Upgrade struct {
	HomeDir        string
	CurrVersion    string
	RemoteVersion  string
	LastestVersion string
}

const (
	upHost          = "http://binbin.run/afrog-release"
	upPathName      = "/afrog-pocs"
	upPath          = "/afrog-pocs.zip"
	upRemoteVersion = "/version"
)

func New() *Upgrade {
	homeDir, _ := os.UserHomeDir()
	return &Upgrade{HomeDir: homeDir}
}

func (u *Upgrade) CheckUpgrade() (bool, error) {
	curVersion, err := poc.GetPocVersionNumber()
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

	u.CurrVersion = curVersion
	u.RemoteVersion = strings.TrimSpace(string(remoteVersion))

	return utils.Compare(strings.TrimSpace(string(remoteVersion)), ">", curVersion), nil
}

func (u *Upgrade) UpgradeAfrogPocs() {
	isUp, err := u.CheckUpgrade()
	if err != nil {
		u.LastestVersion = u.CurrVersion
		return
	}
	if !isUp {
		u.LastestVersion = u.CurrVersion
		return
	}
	if isUp {
		fmt.Println(log.LogColor.Info("Downloading latest release..."))
		u.LastestVersion = u.RemoteVersion
		u.Download()
	}
}

func (u *Upgrade) Download() {
	resp, err := grab.Get(u.HomeDir, upHost+upPath)
	if err != nil {
		fmt.Println(log.LogColor.Low(err.Error()))
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
		fmt.Println(log.LogColor.Low("Failed updated afrog-pocs ", err))
	}

	fmt.Println(log.LogColor.Info("Successfully updated afrog-pocs to ", u.HomeDir+upPathName))
}
