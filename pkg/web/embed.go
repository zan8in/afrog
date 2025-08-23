package web

import "embed"

//go:embed build/**/*
var buildFS embed.FS
