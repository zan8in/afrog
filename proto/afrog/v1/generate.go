// Package afrogv1 是 AfrogScanner / AfrogAgent 的生成代码，源头是 afrog.proto。
//
// 重新生成：
//
//	cd proto/afrog/v1 && go generate ./...
//
// 依赖 protoc 以及 protoc-gen-go、protoc-gen-go-grpc 两个插件（go install 即可）。
package afrogv1

//go:generate protoc -I . --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative afrog.proto
