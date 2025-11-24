package web

import "embed"

//go:embed all:webpath
var webpathFS embed.FS

func GetWebpathFS() embed.FS {
	return webpathFS
}

func GetWebpathIndexPath() string {
	return "index.html"
}
