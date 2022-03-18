package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/log"
)

func main() {
	color := log.NewColor()

	color.Critical("helllo")

	fmt.Printf("%s,%s,%s,%s,%s,%s,%s\n", color.Info("Info"), color.Low("Low"), color.Midium("Medium"), color.High("High"), color.Critical("Critical"), color.Vulner("Vulner"), color.Time("Time"))

	// info := color.FgBlue.Render
	// low := color.FgCyan.Render
	// medium := color.FgYellow.Render
	// high := color.FgLightRed.Render
	// critical := color.FgRed.Render
	// vulner := color.FgLightGreen.Render
	// // red := color.FgRed.Render
	// // green := color.FgGreen.Render
	// fmt.Printf("%s  %s %s  %s %s  %s \n", info("Command"), low("color"), medium("medium"), high("high"), critical("critical"), vulner("vulner"))
}
