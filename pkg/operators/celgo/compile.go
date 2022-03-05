package celgo

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/zan8in/afrog/pkg/proto"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	NewEnvOptions = []cel.EnvOption{
		cel.Container("proto"),
		cel.Types(
			&proto.UrlType{},
			&proto.Request{},
			&proto.Response{},
			&proto.Reverse{},
		),
		cel.Declarations(
			decls.NewVar("request", decls.NewObjectType("proto.Request")),
			decls.NewVar("response", decls.NewObjectType("proto.Response")),
		),
		cel.Declarations(
			// functions
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("icontains",
				decls.NewInstanceOverload("string_icontains_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("randomInt",
				decls.NewOverload("randomInt_int_int",
					[]*exprpb.Type{decls.Int, decls.Int},
					decls.Int)),
			decls.NewFunction("randomLowercase",
				decls.NewOverload("randomLowercase_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
		),
	}
)

func ReadComplieOptions(reg ref.TypeRegistry) []cel.EnvOption {
	allEnvOptions := []cel.EnvOption{
		cel.CustomTypeAdapter(reg),
		cel.CustomTypeProvider(reg),
	}
	allEnvOptions = append(allEnvOptions, NewEnvOptions...)
	return allEnvOptions
}

//	追加rule变量到 cel options
func WriteRuleIsVulOptions(c CustomLib, key string, isVul bool) {
	c.envOptions = append(c.envOptions, cel.Declarations(decls.NewVar(key+"()", decls.Bool)))
}
