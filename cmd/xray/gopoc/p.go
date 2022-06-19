package _go

import "fmt"

type ScriptScanArgs struct {
	Host    string
	Port    uint16
	IsHTTPS bool
}

type Result2 struct {
	IsVul    bool
	Request  string
	Response string
}

type ScriptScanFunc func(args *ScriptScanArgs) (Result2, error)

var scriptHandles = map[string]ScriptScanFunc{}

func GetScriptFunc(pocName string) ScriptScanFunc {
	if r, err := scriptHandles[pocName]; err {
		return r
	}
	return nil
}

func ScriptRegister(pocName string, handler ScriptScanFunc) {
	if GetScriptFunc(pocName) != nil {
		fmt.Println(pocName + "已存在")
		return
	}
	scriptHandles[pocName] = handler
}

func Size() int {
	return len(scriptHandles)
}
