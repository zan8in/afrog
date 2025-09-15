package web

import "embed"

//go:embed webpath
var webpathFS embed.FS

func GetWebpathFS() embed.FS {
	return webpathFS
}
