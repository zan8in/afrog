package celgo

import (
	"strings"

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

//	如果有set：追加set变量到 cel options
//	这里得注意下 reverse的顺序问题 map可能是随机的
func WriteRuleSetOptions(c CustomLib, key string, args map[string]interface{}) {
	for k, v := range args {
		// 在执行之前是不知道变量的类型的，所以统一声明为字符型
		// 所以randomInt虽然返回的是int型，在运算中却被当作字符型进行计算，需要重载string_*_string
		var d *exprpb.Decl
		switch vv := v.(type) {
		case int64:
			d = decls.NewVar(key+"."+k, decls.Int)
		case string:
			if strings.HasPrefix(vv, "newReverse") {
				d = decls.NewVar(key+"."+k, decls.NewObjectType("gocel.Reverse"))
			} else if strings.HasPrefix(vv, "randomInt") {
				d = decls.NewVar(key+"."+k, decls.Int)
			} else {
				d = decls.NewVar(key+"."+k, decls.String)
			}
		default:
			d = decls.NewVar(key+"."+k, decls.String)
		}

		c.envOptions = append(c.envOptions, cel.Declarations(d))
	}
}

//	追加rule变量到 cel options
func WriteRuleIsVulOptions(c CustomLib, key string, isVul bool) {
	c.envOptions = append(c.envOptions, cel.Declarations(decls.NewVar(key+"()", decls.Bool)))
}
