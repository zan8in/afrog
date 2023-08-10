package gox

import (
	"fmt"

	"github.com/zan8in/shiro"
)

func shiro_key(target string, variableMap map[string]any) error {
	s, err := shiro.NewShiro()
	if err != nil {
		return err
	}

	result, err := s.Run(shiro.Options{
		Target: target,
	})
	if err != nil {
		return err
	}

	if result == nil {
		return fmt.Errorf("result is nil")
	}

	setRequest(target, variableMap)

	if len(result.ShiroKey) > 0 {
		data := fmt.Sprintf("ShiroKey: %s\r\nRememberMe: %s\r\n", result.ShiroKey, result.RememberMe)
		setResponse(data, variableMap)
	}

	setFullTarget(target, variableMap)

	return nil
}

func init() {
	funcMap["shiro_key"] = shiro_key
}
