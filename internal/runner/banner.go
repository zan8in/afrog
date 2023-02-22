package runner

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/config"
	"github.com/zan8in/afrog/pkg/log"
	"github.com/zan8in/afrog/pkg/upgrade"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/gologger"
)

var banner1 = fmt.Sprintf(`
┌─┐┌─┐┬─┐┌─┐┌─┐
├─┤├┤ ├┬┘│ ││ ┬
┴ ┴└  ┴└─└─┘└─┘ %s
`, config.Version)
var banner2 = fmt.Sprintf(`
╔═╗╔═╗╦═╗╔═╗╔═╗
╠═╣╠╣ ╠╦╝║ ║║ ╦
╩ ╩╚  ╩╚═╚═╝╚═╝ %s
`, config.Version)
var banner3 = fmt.Sprintf(`
╔═╗┌─┐┬─┐┌─┐┌─┐
╠═╣├┤ ├┬┘│ ││ ┬
╩ ╩└  ┴└─└─┘└─┘ %s
`, config.Version)
var banner4 = fmt.Sprintf(`
┌─┐╔═╗╦═╗╔═╗╔═╗
├─┤╠╣ ╠╦╝║ ║║ ╦
┴ ┴╚  ╩╚═╚═╝╚═╝ %s
`, config.Version)

var banner5 = fmt.Sprintf(`
╔═╗┌─┐╦═╗┌─┐╔═╗
╠═╣├┤ ╠╦╝│ │║ ╦
╩ ╩└  ╩╚═└─┘╚═╝ %s
`, config.Version)
var banner6 = fmt.Sprintf(`
┌─┐╔═╗┬─┐╔═╗┌─┐
├─┤╠╣ ├┬┘║ ║│ ┬
┴ ┴╚  ┴└─╚═╝└─┘ %s
`, config.Version)

func ShowBanner() {
	gologger.Print().Msgf("%s\n", randomBanner())
	gologger.Print().Msgf("\tThe Wandering Earth 2\n\n")
}

func randomBanner() string {
	switch utils.GetRandomIntWithAll(1, 6) {
	case 1:
		return banner1
	case 2:
		return banner2
	case 3:
		return banner3
	case 4:
		return banner4
	case 5:
		return banner5
	case 6:
		return banner6
	}
	return banner1
}

func ShowBanner2(upgrade *upgrade.Upgrade) {
	messageStr := ""
	if utils.Compare(upgrade.LastestAfrogVersion, ">", config.Version) {
		messageStr = " (" + log.LogColor.Red(upgrade.LastestAfrogVersion) + ")"
	} else {
		messageStr = " (" + log.LogColor.Green("latest") + ")"
	}
	gologger.Info().Msgf("Using afrog Engine %s%s", config.Version, messageStr)

	messageStr2 := ""
	if utils.Compare(upgrade.LastestVersion, ">", upgrade.CurrVersion) {
		messageStr2 = " (" + log.LogColor.Red(upgrade.LastestVersion) + ")"
	} else {
		messageStr2 = " (" + log.LogColor.Green("latest") + ")"
	}
	gologger.Info().Msgf("Using afrog-pocs %s%s", upgrade.CurrVersion, messageStr2)
}

// func ShowUsage() string {
// 	return "\nUSAGE:\n   afrog -t example.com -o result.html\n   afrog -T urls.txt -o result.html\n   afrog -T urls.txt -s -o result.html\n   afrog -t example.com -P ./pocs/poc-test.yaml -o result.html\n   afrog -t example.com -P ./pocs/ -o result.html\n"
// }

// func ShowTips() string {
// 	return "\nTIPS:\n   " + utils.GetRandomTips() + "\n"
// }
