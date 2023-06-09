package jndi

import (
	"strings"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/protocols/http/retryhttpclient"
)

// https://github.com/r00tSe7en/JNDIMonitor
func Jndilogchek(randomstr string) bool {
	url := "http://" + config.ReverseJndi + ":" + config.ReverseApiPort + "/?api=" + randomstr

	resp, _, err := retryhttpclient.Get(url)
	if err != nil {
		log.Log().Error(err.Error())
		return false
	}
	if strings.Contains(string(resp), "yes") {
		return true
	}
	return false
}
