package _go

import "fmt"

func afrogGoPocTest2(ssa *ScriptScanArgs) (Result2, error) {
	fmt.Println("AfrogGoPocTest2...")
	return Result2{}, nil
}

func init() {
	ScriptRegister("test2", afrogGoPocTest2)
}
