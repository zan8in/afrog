package gox

func demo(target string, variableMap map[string]any) error {
	data := "hello world"
	setRequest(target+"\r\n"+data, variableMap)

	body := "hello world"
	setResponse(body, variableMap)

	setFullTarget(target, variableMap)

	return nil
}

func init() {
	funcMap["demo"] = demo
}
