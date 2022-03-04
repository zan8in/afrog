package errors

import "errors"

func NewCelEnvError(err error) error {
	return errors.New("NewCelEnv Error: " + err.Error())
}

func NewEvalError(err error) error {
	return errors.New("Eval Error: " + err.Error())
}

func NewEvalTypeError(err string) error {
	return errors.New("Eval Result Type Error: " + err)
}
