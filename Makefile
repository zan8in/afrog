# 本地构建入口。
#
# 这里不再注入版本号，避免 dev 构建显示成 3.5.9-16-g74124eda-dirty 这类长串：
#   - 正式发布：GoReleaser 用 -X 注入 git tag（见 .goreleaser.yaml）；
#   - 本地构建：Go 1.24+ 的 VCS 版本戳记给出「上一个 tag + 1」的伪版本，
#     代码里（pkg/config/banner.go）把伪版本归一化成干净版本号，如 3.5.10；
#   - 无 .git（导出的源码包）：回落到 dev。
#
# 需要显式指定版本时可覆盖：make build VERSION=3.5.10

VERSION_LDFLAG := $(if $(VERSION),-X github.com/zan8in/afrog/v3/pkg/config.Version=$(VERSION))
LDFLAGS := -s -w $(VERSION_LDFLAG)

.PHONY: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o afrog ./cmd/afrog
