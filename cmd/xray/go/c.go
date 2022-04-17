package _go

import "fmt"

func afrogGoPocTest3(ssa *ScriptScanArgs) (Result2, error) {
	fmt.Println("AfrogGoPocTest3...")
	return Result2{}, nil
}

func init() {
	ScriptRegister("test3", afrogGoPocTest3)
}
