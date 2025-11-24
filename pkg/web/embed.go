package web

import "embed"

//go:embed webpath/*.*
//go:embed webpath/fonts/*/*.*
//go:embed webpath/_app/*.*
//go:embed webpath/_app/immutable/*/*.*
var webpathFS embed.FS

func GetWebpathFS() embed.FS {
	return webpathFS
}

func GetWebpathIndexPath() string {
	return "index.html"
}
