package gox

import (
	"fmt"
	"reflect"

	"github.com/zan8in/afrog/pkg/proto"
	"github.com/zan8in/gologger"
)

var funcMap = map[string]any{}

func Request(target, data string, variableMap map[string]any) error {
	err := callFunction(data, []any{target, variableMap}, funcMap)
	if err != nil {
		return err.(error)
	}
	return nil
}

func callFunction(name string, args []interface{}, funcMap map[string]interface{}) interface{} {
	f, ok := funcMap[name]
	if !ok {
		gologger.Debug().Msgf(fmt.Sprintf("function %s not found", name))
		return nil
	}

	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Func {
		gologger.Debug().Msgf(fmt.Sprintf("%s is not a function", name))
		return nil
	}
	in := make([]reflect.Value, len(args))
	for i, arg := range args {
		in[i] = reflect.ValueOf(arg)
	}
	out := v.Call(in)
	if len(out) == 0 {
		return nil
	}
	return out[0].Interface()
}

func setRequest(data string, vmap map[string]any) {
	vmap["request"] = &proto.Request{
		Raw: []byte(data),
	}
}

func setResponse(data string, vmap map[string]any) {
	vmap["response"] = &proto.Response{
		Raw: []byte(data),
	}
}

func setFullTarget(data string, vmap map[string]any) {
	vmap["fulltarget"] = data
}
