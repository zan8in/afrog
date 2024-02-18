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
	"github.com/zan8in/afrog/pkg/log"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"gopkg.in/yaml.v2"
)

type CustomLib struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

func (c *CustomLib) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	return c.programOptions
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
	c := &CustomLib{}
	reg := types.NewEmptyRegistry()
	c.envOptions = ReadComplieOptions(reg)
	c.programOptions = ReadProgramOptions(reg)
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

		var d *exprpb.Decl
		switch vv := value.(type) {
		case int64:
			d = decls.NewVar(key, decls.Int)
		case string:
			if strings.HasPrefix(vv, "newReverse") {
				d = decls.NewVar(key, decls.NewObjectType("proto.Reverse"))
			} else if strings.HasPrefix(vv, "randomInt") {
				d = decls.NewVar(key, decls.Int)
			} else {
				d = decls.NewVar(key, decls.String)
			}
		case map[string]string:
			d = decls.NewVar(key, StrStrMapType)
		default:
			d = decls.NewVar(key, decls.String)
		}
		c.envOptions = append(c.envOptions, cel.Declarations(d))
	}
}

func (c *CustomLib) WriteRuleFunctionsROptions(funcName string, returnBool bool) {
	c.envOptions = append(c.envOptions, cel.Declarations(
		decls.NewFunction(funcName,
			decls.NewOverload(funcName,
				[]*exprpb.Type{},
				decls.Bool)),
	),
	)

	c.programOptions = append(c.programOptions, cel.Functions(
		&functions.Overload{
			Operator: funcName,
			Function: func(values ...ref.Val) ref.Val {
				return types.Bool(returnBool)
			},
		}))
}

func (c *CustomLib) UpdateCompileOption(k string, t *exprpb.Type) {
	c.envOptions = append(c.envOptions, cel.Declarations(decls.NewVar(k, t)))
}

func (c *CustomLib) Reset() {
	*c = CustomLib{}
}
