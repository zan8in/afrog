package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/zan8in/afrog/v3/pkg/log"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"gopkg.in/yaml.v2"
)

type CustomLib struct {
	baseEnvOptions     []cel.EnvOption
	baseProgramOptions []cel.ProgramOption
	varTypes           map[string]*exprpb.Type
	ruleFuncs          map[string]bool
}

func (c *CustomLib) CompileOptions() []cel.EnvOption {
	opts := make([]cel.EnvOption, 0, len(c.baseEnvOptions)+2)
	opts = append(opts, c.baseEnvOptions...)

	if len(c.varTypes) > 0 {
		varDecls := make([]*exprpb.Decl, 0, len(c.varTypes))
		for k, t := range c.varTypes {
			varDecls = append(varDecls, decls.NewVar(k, t))
		}
		opts = append(opts, cel.Declarations(varDecls...))
	}

	if len(c.ruleFuncs) > 0 {
		fnDecls := make([]*exprpb.Decl, 0, len(c.ruleFuncs))
		for name := range c.ruleFuncs {
			fnDecls = append(fnDecls, decls.NewFunction(name,
				decls.NewOverload(name, []*exprpb.Type{}, decls.Bool),
			))
		}
		opts = append(opts, cel.Declarations(fnDecls...))
	}

	return opts
}

func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	opts := make([]cel.ProgramOption, 0, len(c.baseProgramOptions)+1)
	opts = append(opts, c.baseProgramOptions...)

	if len(c.ruleFuncs) > 0 {
		overloads := make([]*functions.Overload, 0, len(c.ruleFuncs))
		for name, ret := range c.ruleFuncs {
			fnName := name
			fnRet := ret
			overloads = append(overloads, &functions.Overload{
				Operator: fnName,
				Function: func(values ...ref.Val) ref.Val {
					return types.Bool(fnRet)
				},
			})
		}
		opts = append(opts, cel.Functions(overloads...))
	}

	return opts
}

func (c *CustomLib) RunEval(expression string, variablemap map[string]any) (ref.Val, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	var (
		val ref.Val
		err error
	)
	resp := make(chan int)
	go func() {
		defer close(resp)

		env, err := c.NewCelEnv()
		if err != nil {
			resp <- 9
		}
		val, err = Eval(env, expression, variablemap)
		if err != nil {
			resp <- 9
		}
		resp <- 99
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("Eval timed out")
	case v := <-resp:
		if v == 99 {
			return val, err
		}
		return nil, fmt.Errorf("Eval error")
	}

}

func NewCustomLib() *CustomLib {
	c := &CustomLib{
		varTypes:  make(map[string]*exprpb.Type),
		ruleFuncs: make(map[string]bool),
	}
	reg := types.NewEmptyRegistry()
	c.baseEnvOptions = ReadComplieOptions(reg)
	c.baseProgramOptions = ReadProgramOptions(reg)
	return c
}

func (c *CustomLib) NewCelEnv() (env *cel.Env, err error) {
	env, err = cel.NewEnv(cel.Lib(c))
	return env, err
}

func Eval(env *cel.Env, expression string, params map[string]any) (ref.Val, error) {
	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		log.Log().Error(fmt.Sprintf("cel env.Compile err, %s", iss.Err().Error()))
		return nil, iss.Err()
	}
	prg, err := env.Program(ast)
	if err != nil {
		log.Log().Error(fmt.Sprintf("cel env.Program err, %s", err.Error()))
		return nil, err
	}
	out, _, err := prg.Eval(params)
	if err != nil {
		log.Log().Error(fmt.Sprintf("cel prg.Eval err, %s", err.Error()))
		return nil, err
	}
	return out, nil
}

func (c *CustomLib) WriteRuleSetOptions(args yaml.MapSlice) {
	for _, v := range args {
		key := v.Key.(string)
		value := v.Value

		var t *exprpb.Type
		switch vv := value.(type) {
		case int64:
			t = decls.Int
		case string:
			if strings.HasPrefix(vv, "newReverse") {
				t = decls.NewObjectType("proto.Reverse")
			} else if strings.HasPrefix(vv, "newOOB") {
				t = decls.NewObjectType("proto.OOB")
			} else if strings.HasPrefix(vv, "randomInt") {
				t = decls.Int
			} else {
				t = decls.String
			}
		case map[string]string:
			t = StrStrMapType
		default:
			t = decls.String
		}
		c.UpdateCompileOption(key, t)
	}
}

func (c *CustomLib) WriteRuleFunctionsROptions(funcName string, returnBool bool) {
	c.ruleFuncs[funcName] = returnBool
}

func (c *CustomLib) UpdateCompileOption(k string, t *exprpb.Type) {
	if c.varTypes == nil {
		c.varTypes = make(map[string]*exprpb.Type)
	}
	c.varTypes[k] = t
}

func (c *CustomLib) Reset() {
	*c = *NewCustomLib()
}
