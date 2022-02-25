package gocel

import (
	"bytes"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
)

var (
	NewProgramOptions = []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "bytes_bcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(v1, v2))
				},
			},
		),
	}
)

func GetProgramOptions(reg ref.TypeRegistry) []cel.ProgramOption {
	allProgramOpitons := []cel.ProgramOption{}
	allProgramOpitons = append(allProgramOpitons, NewProgramOptions...)
	return allProgramOpitons
}
