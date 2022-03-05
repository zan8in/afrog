package celgo

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/zan8in/afrog/pkg/errors"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
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

var CustomLibPool = sync.Pool{
	New: func() interface{} {
		return CustomLib{}
	},
}

func (c *CustomLib) Run(expression string, variablemap map[string]interface{}, call runCallback) {
	env, err := c.NewCelEnv()
	if err != nil {
		call(nil, errors.NewCelEnvError(err))
		return
	}
	val, err := Eval(env, expression, variablemap)
	if err != nil {
		call(nil, errors.NewEvalError(err))
		return
	}
	isVul, ok := val.Value().(bool)
	if !ok {
		fmt.Println("successVal Value error: ", err.Error())
		return
	}
	call(isVul, err)
}

func (c *CustomLib) RunEval(expression string, variablemap map[string]interface{}) (ref.Val, error) {
	env, err := c.NewCelEnv()
	if err != nil {
		return nil, errors.NewCelEnvError(err)
	}
	val, err := Eval(env, expression, variablemap)
	if err != nil {
		return nil, errors.NewEvalError(err)
	}
	return val, nil
}

type runCallback func(interface{}, error)

// Step 1: 创建 cel 库
func NewCustomLib() CustomLib {
	c := CustomLibPool.Get().(CustomLib)
	reg := types.NewEmptyRegistry()

	c.envOptions = ReadComplieOptions(reg)
	c.programOptions = ReadProgramOptions(reg)
	return c
}

// Step 2: 创建 cel 环境
func (c *CustomLib) NewCelEnv() (env *cel.Env, err error) {
	env, err = cel.NewEnv(cel.Lib(c))
	return env, err
}

// Step 3: 执行表达式
// @env cel.Env cel环境
// @expression string gocel表达式
// @params map[string]interface 表达式变量值
func Eval(env *cel.Env, expression string, params map[string]interface{}) (ref.Val, error) {
	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	out, _, err := prg.Eval(params)
	if err != nil {
		return nil, err
	}
	return out, nil
}

//	如果有set：追加set变量到 cel options
//	这里得注意下 reverse的顺序问题 map可能是随机的
func (c *CustomLib) WriteRuleSetOptions(args map[string]interface{}) {
	for k, v := range args {
		// 在执行之前是不知道变量的类型的，所以统一声明为字符型
		// 所以randomInt虽然返回的是int型，在运算中却被当作字符型进行计算，需要重载string_*_string
		var d *exprpb.Decl
		switch vv := v.(type) {
		case int64:
			d = decls.NewVar(k, decls.Int)
		case string:
			if strings.HasPrefix(vv, "newReverse") {
				d = decls.NewVar(k, decls.NewObjectType("gocel.Reverse"))
			} else if strings.HasPrefix(vv, "randomInt") {
				d = decls.NewVar(k, decls.Int)
			} else {
				d = decls.NewVar(k, decls.String)
			}
		default:
			d = decls.NewVar(k, decls.String)
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
