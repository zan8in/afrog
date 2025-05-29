package runner

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/zan8in/afrog/v3/pkg/proto"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	StrStrMapType = decls.NewMapType(decls.String, decls.String)
	NewEnvOptions = []cel.EnvOption{
		cel.Container("proto"),
		cel.Types(
			&proto.UrlType{},
			&proto.Request{},
			&proto.Response{},
			&proto.Reverse{},
			&proto.OOB{},
			StrStrMapType,
		),
		cel.Declarations(
			decls.NewVar("request", decls.NewObjectType("proto.Request")),
			decls.NewVar("response", decls.NewObjectType("proto.Response")),
			// decls.NewVar("reverse", decls.NewObjectType("proto.Reverse")),
		),
		cel.Declarations(
			// string
			decls.NewFunction("icontains",
				decls.NewInstanceOverload("string_icontains_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("substr",
				decls.NewOverload("substr_string_int_int",
					[]*exprpb.Type{decls.String, decls.Int, decls.Int},
					decls.String)),
			decls.NewFunction("replaceAll",
				decls.NewOverload("replaceAll_string_string_string",
					[]*exprpb.Type{decls.String, decls.String, decls.String},
					decls.String)),
			decls.NewFunction("printable",
				decls.NewOverload("printable_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("toUintString",
				decls.NewOverload("toUintString_string_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.String)),
			decls.NewFunction("toUpper",
				decls.NewOverload("toUpper_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("toLower",
				decls.NewOverload("toLower_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			// []byte
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("ibcontains",
				decls.NewInstanceOverload("bytes_ibcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("bstartsWith",
				decls.NewInstanceOverload("bytes_bstartsWith_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			// encode
			decls.NewFunction("md5",
				decls.NewOverload("md5_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("faviconHash",
				decls.NewOverload("faviconHash_stringOrBytes",
					[]*exprpb.Type{decls.Any},
					decls.Int)),
			decls.NewFunction("hexdecode",
				decls.NewOverload("hexdecode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			// random
			decls.NewFunction("randomInt",
				decls.NewOverload("randomInt_int_int",
					[]*exprpb.Type{decls.Int, decls.Int},
					decls.Int)),
			decls.NewFunction("randomLowercase",
				decls.NewOverload("randomLowercase_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			// regex
			decls.NewFunction("submatch",
				decls.NewInstanceOverload("string_submatch_string",
					[]*exprpb.Type{decls.String, decls.String},
					StrStrMapType,
				)),
			decls.NewFunction("bsubmatch",
				decls.NewInstanceOverload("string_bsubmatch_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					StrStrMapType,
				)),
			decls.NewFunction("bmatches",
				decls.NewInstanceOverload("string_bmatches_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					decls.Bool)),
			// reverse
			decls.NewFunction("wait",
				decls.NewInstanceOverload("reverse_wait_int",
					[]*exprpb.Type{decls.Any, decls.Int},
					decls.Bool)),
			decls.NewFunction("jndi",
				decls.NewInstanceOverload("reverse_jndi_int",
					[]*exprpb.Type{decls.Any, decls.Int},
					decls.Bool)),
			decls.NewFunction("oobCheck",
				decls.NewOverload("oobCheck_oob_string_int",
					[]*exprpb.Type{decls.Any, decls.String, decls.Int},
					decls.Bool)),
			// other
			decls.NewFunction("sleep",
				decls.NewOverload("sleep_int", []*exprpb.Type{decls.Int},
					decls.Null)),
			// year
			decls.NewFunction("year",
				decls.NewOverload("year_string", []*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("shortyear",
				decls.NewOverload("shortyear_string", []*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("month",
				decls.NewOverload("month_string", []*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("day",
				decls.NewOverload("day_string", []*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("timestamp_second",
				decls.NewOverload("timestamp_second_string", []*exprpb.Type{decls.Int},
					decls.String)),
			// compare version
			decls.NewFunction("versionCompare",
				decls.NewOverload("versionCompare_string_string_string",
					[]*exprpb.Type{decls.String, decls.String, decls.String},
					decls.Bool)),
			// Ysoserial
			decls.NewFunction("ysoserial",
				decls.NewOverload("ysoserial_string_string_string",
					[]*exprpb.Type{decls.String, decls.String, decls.String},
					decls.String)),
			// AesCBC
			decls.NewFunction("aesCBC",
				decls.NewOverload("aesCBC_string_string_string",
					[]*exprpb.Type{decls.String, decls.String, decls.String},
					decls.String)),
			// Repeat
			decls.NewFunction("repeat",
				decls.NewOverload("repeat_string_int",
					[]*exprpb.Type{decls.String, decls.Int},
					decls.String)),
			// decimal
			decls.NewFunction("decimal",
				decls.NewOverload("decimal_string_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.String)),
			// length
			decls.NewFunction("length",
				decls.NewOverload("length_string",
					[]*exprpb.Type{decls.String},
					decls.Int)),
			decls.NewFunction("length",
				decls.NewOverload("length_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.Int)),
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

// 追加rule变量到 cel options
func WriteRuleIsVulOptions(c CustomLib, key string, isVul bool) {
	c.envOptions = append(c.envOptions, cel.Declarations(decls.NewVar(key+"()", decls.Bool)))
}
