package web

import "embed"

//go:embed webpath/index.html
//go:embed webpath/login.html
//go:embed webpath/docs.html
//go:embed webpath/pocs.html
//go:embed webpath/reports.html
//go:embed webpath/favicon.ico
//go:embed webpath/favicon-16x16.png
//go:embed webpath/favicon-32x32.png
//go:embed webpath/android-chrome-192x192.png
//go:embed webpath/android-chrome-512x512.png
//go:embed webpath/apple-touch-icon.png
//go:embed webpath/site.webmanifest
//go:embed webpath/robots.txt
//go:embed webpath/placeholder.svg
//go:embed webpath/fonts/Geist/*
//go:embed webpath/_app/env.js
//go:embed webpath/_app/immutable/assets/*
//go:embed webpath/_app/immutable/chunks/*
//go:embed webpath/_app/immutable/entry/*
//go:embed webpath/_app/immutable/nodes/*
var webpathFS embed.FS

func GetWebpathFS() embed.FS {
	return webpathFS
}

func GetWebpathIndexPath() string {
	return "index.html"
}
