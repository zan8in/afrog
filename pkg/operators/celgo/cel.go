package celgo

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/zan8in/afrog/pkg/xfrog/errors"
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

func (c *CustomLib) RunEval(expression string, variablemap map[string]interface{}) (bool, error) {
	env, err := c.NewCelEnv()
	if err != nil {
		return false, errors.NewCelEnvError(err)
	}
	val, err := Eval(env, expression, variablemap)
	if err != nil {
		return false, errors.NewEvalError(err)
	}
	isVul, ok := val.Value().(bool)
	if !ok {
		fmt.Println("successVal Value error: ", err.Error())
		return isVul, err
	}
	return isVul, nil
}

type runCallback func(interface{}, error)

// Step 1: 创建 cel 库
func NewCustomLib() CustomLib {
	c := CustomLib{}
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
