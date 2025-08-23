package web

import "embed"

//go:embed build/**/* build/*.* build/**/**/* build/**/**/*.* build/**/**/**/* build/**/**/**/*.*
var buildFS embed.FS
