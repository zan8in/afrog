package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	var language string
	var severity *cli.StringSlice

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "search",
				Aliases:     []string{"s"},
				Usage:       "language for the greeting",
				Destination: &language,
			},
			&cli.StringSliceFlag{
				Name:        "severity",
				Aliases:     []string{"se"},
				Usage:       "pocs to run based on severity. Possible values: info, low, medium, high, critical",
				Destination: severity,
			},
		},
		Action: func(c *cli.Context) error {
			fmt.Println(language)
			fmt.Println(severity.String())
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
