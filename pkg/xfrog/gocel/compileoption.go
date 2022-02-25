package gocel

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	NewEnvOptions = []cel.EnvOption{
		cel.Types(
			&UrlType{},
			&Request{},
			&Response{},
			&Reverse{},
		),
		cel.Declarations(
			decls.NewVar("request", decls.NewObjectType("gocel.Request")),
			decls.NewVar("response", decls.NewObjectType("gocel.Response")),
			decls.NewVar("reverse", decls.NewObjectType("gocel.Rerverse")),
		),
		cel.Declarations(
			// functions
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
		),
	}
)

func GetComplieOptions(reg ref.TypeRegistry) []cel.EnvOption {
	allEnvOptions := []cel.EnvOption{
		cel.CustomTypeAdapter(reg),
		cel.CustomTypeProvider(reg),
	}
	allEnvOptions = append(allEnvOptions, NewEnvOptions...)
	return allEnvOptions
}
