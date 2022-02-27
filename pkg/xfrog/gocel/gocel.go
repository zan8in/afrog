package gocel

import (
	"fmt"
	sync "sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/zan8in/afrog/pkg/xfrog/errors"
)

func Run(expression string, variablemap map[string]interface{}, call runCallback) {
	//NewCustomLib()
	env, err := NewCelEnv()
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

type runCallback func(interface{}, error)

var (
	CustomLibPool = sync.Pool{
		New: func() interface{} {
			return CustomLib{}
		},
	}
)

func GetCustomLibPool() CustomLib {
	return CustomLibPool.Get().(CustomLib)
}

func SetCustomLibPool(c CustomLib) {
	CustomLibPool.Put(c)
}

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

// Step 1: 创建 cel 库
func NewCustomLib() {
	c := GetCustomLibPool()

	reg := types.NewEmptyRegistry()

	c.envOptions = GetComplieOptions(reg)
	c.programOptions = GetProgramOptions(reg)

	SetCustomLibPool(c)
}

// Step 2: 创建 cel 环境
func NewCelEnv() (env *cel.Env, err error) {
	c := GetCustomLibPool()
	env, err = cel.NewEnv(cel.Lib(&c))
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
