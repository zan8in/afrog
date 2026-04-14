package runner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/zan8in/afrog/v3/pkg/log"
	"github.com/zan8in/afrog/v3/pkg/proto"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"gopkg.in/yaml.v2"
)

type CustomLib struct {
	baseEnvOptions     []cel.EnvOption
	baseProgramOptions []cel.ProgramOption
	varTypes           map[string]*exprpb.Type
	ruleFuncs          map[string]bool
	oobMgr             *OOBManager
	currentOOB         *proto.OOB
	lastOOBHit         *OOBHitSnapshot
	lastOOBPending     []OOBPending
}

type OOBPending struct {
	Filter     string
	FilterType string
	TimeoutSec int64
	Token      string
}

func (c *CustomLib) CompileOptions() []cel.EnvOption {
	opts := make([]cel.EnvOption, 0, len(c.baseEnvOptions)+2)
	opts = append(opts, c.baseEnvOptions...)

	opts = append(opts, cel.Declarations(
		decls.NewFunction("oobCheck",
			decls.NewOverload("oobCheck_string_int",
				[]*exprpb.Type{decls.String, decls.Int},
				decls.Bool)),
		decls.NewFunction("oobCheckToken",
			decls.NewOverload("oobCheckToken_string_int_string",
				[]*exprpb.Type{decls.String, decls.Int, decls.String},
				decls.Bool)),
		decls.NewFunction("oobEvidence",
			decls.NewOverload("oobEvidence",
				[]*exprpb.Type{},
				decls.String)),
	))

	if len(c.varTypes) > 0 {
		keys := make([]string, 0, len(c.varTypes))
		for k := range c.varTypes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		varDecls := make([]*exprpb.Decl, 0, len(keys))
		for _, k := range keys {
			t := c.varTypes[k]
			varDecls = append(varDecls, decls.NewVar(k, t))
		}
		opts = append(opts, cel.Declarations(varDecls...))
	}

	if len(c.ruleFuncs) > 0 {
		names := make([]string, 0, len(c.ruleFuncs))
		for name := range c.ruleFuncs {
			names = append(names, name)
		}
		sort.Strings(names)
		fnDecls := make([]*exprpb.Decl, 0, len(names))
		for _, name := range names {
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
		names := make([]string, 0, len(c.ruleFuncs))
		for name := range c.ruleFuncs {
			names = append(names, name)
		}
		sort.Strings(names)
		overloads := make([]*functions.Overload, 0, len(names))
		for _, name := range names {
			ret := c.ruleFuncs[name]
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

	opts = append(opts, cel.Functions(
		&functions.Overload{
			Operator: "oobCheck_string_int",
			Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
				filterType, ok := lhs.(types.String)
				if !ok {
					return types.ValOrErr(lhs, "unexpected type '%v' passed to oobCheck", lhs.Type())
				}
				timeout, ok := rhs.(types.Int)
				if !ok {
					return types.ValOrErr(rhs, "unexpected type '%v' passed to oobCheck", rhs.Type())
				}

				mgr := c.oobMgr
				oob := c.currentOOB
				if mgr == nil || oob == nil || strings.TrimSpace(oob.Filter) == "" {
					return types.Bool(false)
				}

				ft := strings.TrimSpace(string(filterType))
				if ft == "" {
					ft = "dns"
				}
				to := int64(timeout)
				if to == 0 {
					to = 3
				}
				mgr.Watch(oob.Filter, ft)
				if snap, ok2 := mgr.HitSnapshot(oob.Filter, ft); ok2 {
					c.lastOOBHit = &snap
					return types.Bool(true)
				}
				c.lastOOBPending = append(c.lastOOBPending, OOBPending{Filter: oob.Filter, FilterType: ft, TimeoutSec: to})
				return types.Bool(false)
			},
		},
		&functions.Overload{
			Operator: "oobCheckToken_string_int_string",
			Function: func(values ...ref.Val) ref.Val {
				if len(values) != 3 {
					return types.NewErr("invalid arguments to 'oobCheckToken'")
				}
				filterType, ok := values[0].(types.String)
				if !ok {
					return types.ValOrErr(values[0], "unexpected type '%v' passed to oobCheckToken", values[0].Type())
				}
				timeout, ok := values[1].(types.Int)
				if !ok {
					return types.ValOrErr(values[1], "unexpected type '%v' passed to oobCheckToken", values[1].Type())
				}
				token, ok := values[2].(types.String)
				if !ok {
					return types.ValOrErr(values[2], "unexpected type '%v' passed to oobCheckToken", values[2].Type())
				}

				mgr := c.oobMgr
				oob := c.currentOOB
				if mgr == nil || oob == nil || strings.TrimSpace(oob.Filter) == "" {
					return types.Bool(false)
				}

				ft := strings.TrimSpace(string(filterType))
				if ft == "" {
					ft = "dns"
				}
				to := int64(timeout)
				if to == 0 {
					to = 3
				}
				tok := strings.TrimSpace(string(token))
				mgr.Watch(oob.Filter, ft)
				if snap, ok2 := mgr.HitSnapshot(oob.Filter, ft); ok2 {
					if tok != "" && !strings.Contains(snap.Snippet, tok) {
						c.lastOOBPending = append(c.lastOOBPending, OOBPending{Filter: oob.Filter, FilterType: ft, TimeoutSec: to, Token: tok})
						return types.Bool(false)
					}
					c.lastOOBHit = &snap
					return types.Bool(true)
				}
				c.lastOOBPending = append(c.lastOOBPending, OOBPending{Filter: oob.Filter, FilterType: ft, TimeoutSec: to, Token: tok})
				return types.Bool(false)
			},
		},
		&functions.Overload{
			Operator: "oobEvidence",
			Function: func(values ...ref.Val) ref.Val {
				if len(values) != 0 {
					return types.NewErr("invalid arguments to 'oobEvidence'")
				}
				snap := c.lastOOBHit
				if snap == nil {
					return types.String("")
				}
				if c.oobMgr != nil {
					ev := c.oobMgr.Evidence(snap.Filter, snap.FilterType, 5)
					return types.String(ev)
				}
				if strings.TrimSpace(snap.Snippet) == "" {
					return types.String("")
				}
				meta := fmt.Sprintf("protocol=%s count=%d last_at=%s", snap.FilterType, snap.Count, snap.LastAt.Format(time.RFC3339Nano))
				return types.String(meta + "\n" + snap.Snippet)
			},
		},
	))

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
	normalizeHeaderKeyAccess(ast)
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

func normalizeHeaderKeyAccess(ast *cel.Ast) {
	if ast == nil {
		return
	}
	normalizeHeaderKeyAccessExpr(ast.Expr())
}

func normalizeHeaderKeyAccessExpr(e *exprpb.Expr) {
	if e == nil {
		return
	}

	switch ek := e.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		call := ek.CallExpr
		if call.Target != nil {
			normalizeHeaderKeyAccessExpr(call.Target)
		}
		for _, a := range call.Args {
			normalizeHeaderKeyAccessExpr(a)
		}

		if call.Function == "_[_]" && len(call.Args) == 2 && isRequestOrResponseHeadersSelect(call.Args[0]) {
			lowerStringConst(call.Args[1])
		}
		if (call.Function == "@in" || call.Function == "_in_" || call.Function == "in") && len(call.Args) == 2 && isRequestOrResponseHeadersSelect(call.Args[1]) {
			lowerStringConst(call.Args[0])
		}
	case *exprpb.Expr_SelectExpr:
		if ek.SelectExpr.Operand != nil {
			normalizeHeaderKeyAccessExpr(ek.SelectExpr.Operand)
		}
	case *exprpb.Expr_ListExpr:
		for _, el := range ek.ListExpr.Elements {
			normalizeHeaderKeyAccessExpr(el)
		}
	case *exprpb.Expr_StructExpr:
		for _, ent := range ek.StructExpr.Entries {
			if ent.KeyKind != nil {
				switch kk := ent.KeyKind.(type) {
				case *exprpb.Expr_CreateStruct_Entry_FieldKey:
					_ = kk
				case *exprpb.Expr_CreateStruct_Entry_MapKey:
					normalizeHeaderKeyAccessExpr(kk.MapKey)
				}
			}
			normalizeHeaderKeyAccessExpr(ent.Value)
		}
	case *exprpb.Expr_ComprehensionExpr:
		comp := ek.ComprehensionExpr
		normalizeHeaderKeyAccessExpr(comp.IterRange)
		normalizeHeaderKeyAccessExpr(comp.AccuInit)
		normalizeHeaderKeyAccessExpr(comp.LoopCondition)
		normalizeHeaderKeyAccessExpr(comp.LoopStep)
		normalizeHeaderKeyAccessExpr(comp.Result)
	}
}

func isRequestOrResponseHeadersSelect(e *exprpb.Expr) bool {
	if e == nil {
		return false
	}
	sel := e.GetSelectExpr()
	if sel == nil || sel.Field != "headers" {
		return false
	}
	op := sel.Operand
	if op == nil {
		return false
	}
	id := op.GetIdentExpr()
	if id == nil {
		return false
	}
	return id.Name == "request" || id.Name == "response"
}

func lowerStringConst(e *exprpb.Expr) bool {
	if e == nil {
		return false
	}
	ce := e.GetConstExpr()
	if ce == nil {
		return false
	}
	if _, ok := ce.GetConstantKind().(*exprpb.Constant_StringValue); !ok {
		return false
	}
	ce.ConstantKind = &exprpb.Constant_StringValue{StringValue: strings.ToLower(ce.GetStringValue())}
	return true
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
	if k == "request" || k == "response" {
		return
	}
	if c.varTypes == nil {
		c.varTypes = make(map[string]*exprpb.Type)
	}
	c.varTypes[k] = t
}

func (c *CustomLib) SetOOBManager(mgr *OOBManager) {
	c.oobMgr = mgr
}

func (c *CustomLib) SetCurrentOOB(oob *proto.OOB) {
	c.currentOOB = oob
}

func (c *CustomLib) TakeOOBPending() []OOBPending {
	if c == nil || len(c.lastOOBPending) == 0 {
		return nil
	}
	out := c.lastOOBPending
	c.lastOOBPending = nil
	return out
}

func (c *CustomLib) Reset() {
	*c = *NewCustomLib()
}
