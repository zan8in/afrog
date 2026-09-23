<!--
title: Install
slug: /docs/user-guide/install
lang: en
summary: Installation methods, prerequisites, and verification steps for afrog.
status: published
source: docs/zh/user-guide/02-install.md
last_reviewed: 2026-09-16
-->

`afrog` supports binary downloads, source builds, and `go install`. For most users, the release binary is the fastest way to get started.

## Requirements

- [Go](https://go.dev/) 1.27 or later

If you only use a prebuilt binary, Go is not required in advance. If you build from source or use `go install`, prepare a local Go environment first.

## Installation methods

### Option 1: Download a release binary

Recommended for most users.

```bash
https://github.com/zan8in/afrog/releases/latest
```

Download the executable that matches your platform and place it in your `PATH`.

### Option 2: Build from source

Recommended when you want local debugging, source changes, or development work.

```bash
git clone https://github.com/zan8in/afrog.git
cd afrog
go mod tidy
go build -o afrog cmd/afrog/main.go
./afrog -h
```

### Option 3: Install with Go

Recommended for Go developers who want the latest command directly from source.

```bash
go install -v github.com/zan8in/afrog/v3/cmd/afrog@latest
```

After installation, make sure `$GOBIN` or `$GOPATH/bin` is included in your `PATH`.

## Verify the installation

The most direct check is:

```bash
afrog -h
```

If the command runs and prints the help output, the installation is ready.

## Common issues

### `afrog` command not found

Usually the executable is not on your `PATH`. Check:

- whether the binary is placed in an executable directory
- whether the `go install` output path is on your `PATH`

### `go build` or `go install` fails

Start with these checks:

- the local Go version matches the requirement
- your network can fetch dependencies
- the current repository state is buildable

> **← Previous:** [What afrog does](./01-overview.md) ｜ **Next →:** [First Scan](./03-first-scan.md)
