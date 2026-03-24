package validator

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/zan8in/afrog/v3/pkg/poc"
	"gopkg.in/yaml.v2"
)

type ValidationError struct {
	File    string
	Line    int
	Column  int
	Message string
}

func (e *ValidationError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d:%d: %s", e.File, e.Line, e.Column, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.File, e.Message)
}

type ValidationResult struct {
	File   string
	Passed bool
	Errors []ValidationError
}

// ValidatePocFiles 验证POC文件或目录
func ValidatePocFiles(target string) error {
	var files []string

	// 收集YAML文件
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %v", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no YAML files found in %s", target)
	}

	// 验证每个文件
	var hasErrors bool
	var results []ValidationResult

	for _, file := range files {
		result := validateSinglePocFile(file)
		results = append(results, result)

		if result.Passed {
			fmt.Printf("✅ %s: validation passed\n", file)
		} else {
			hasErrors = true
			fmt.Printf("❌ %s: validation failed\n", file)
			for _, err := range result.Errors {
				fmt.Printf("   %s\n", err.Error())
			}
		}
	}

	if hasErrors {
		// 统计失败和成功的文件数量
		var failedCount, passedCount int
		for _, result := range results {
			if result.Passed {
				passedCount++
			} else {
				failedCount++
			}
		}

		fmt.Printf("\n❌ Validation completed with errors:\n")
		fmt.Printf("   Total files: %d\n", len(files))
		fmt.Printf("   Passed: %d\n", passedCount)
		fmt.Printf("   Failed: %d\n", failedCount)

		return fmt.Errorf("validation failed for %d out of %d files", failedCount, len(files))
	}

	fmt.Printf("\n🎉 All %d files validated successfully!\n", len(files))
	return nil
}

// validateSinglePocFile 验证单个POC文件
func validateSinglePocFile(filePath string) ValidationResult {
	result := ValidationResult{
		File:   filePath,
		Passed: true,
		Errors: []ValidationError{},
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		result.Passed = false
		result.Errors = append(result.Errors, ValidationError{
			File:    filePath,
			Message: fmt.Sprintf("failed to read file: %v", err),
		})
		return result
	}

	var pocData poc.Poc
	if err := yaml.UnmarshalStrict(content, &pocData); err != nil {
		result.Passed = false
		result.Errors = append(result.Errors, parseYamlStrictErrors(filePath, string(content), err)...)
		return result
	}

	// POC结构验证
	if errs := validatePocStructure(&pocData, filePath); len(errs) > 0 {
		result.Passed = false
		result.Errors = append(result.Errors, errs...)
	}

	// Expression语法验证
	if errs := validateExpressions(&pocData, filePath, string(content)); len(errs) > 0 {
		result.Passed = false
		result.Errors = append(result.Errors, errs...)
	}

	return result
}

func parseYamlStrictErrors(filePath, content string, err error) []ValidationError {
	msg := err.Error()
	lines := strings.Split(msg, "\n")
	var out []ValidationError

	appendLine := func(line int, message string) {
		out = append(out, ValidationError{
			File:    filePath,
			Line:    line,
			Column:  0,
			Message: message,
		})
	}

	reLine := regexp.MustCompile(`line (\d+):\s*(.*)`)
	reUnknownField := regexp.MustCompile(`field ([^ ]+) not found in type`)

	if len(lines) > 0 && strings.Contains(lines[0], "unmarshal errors:") {
		for _, l := range lines[1:] {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			m := reLine.FindStringSubmatch(l)
			if len(m) < 3 {
				appendLine(0, fmt.Sprintf("YAML error: %s", l))
				continue
			}
			lineNum, _ := strconv.Atoi(m[1])
			detail := m[2]
			if uf := reUnknownField.FindStringSubmatch(detail); len(uf) >= 2 {
				field := strings.TrimSpace(uf[1])
				hint := hintForUnknownField(field, content)
				if hint != "" {
					appendLine(lineNum, fmt.Sprintf("unsupported field '%s': %s", field, hint))
				} else {
					appendLine(lineNum, fmt.Sprintf("unsupported field '%s'", field))
				}
				continue
			}
			appendLine(lineNum, fmt.Sprintf("YAML error: %s", detail))
		}
		if len(out) > 0 {
			return out
		}
	}

	if m := reLine.FindStringSubmatch(msg); len(m) >= 3 {
		lineNum, _ := strconv.Atoi(m[1])
		detail := m[2]
		if uf := reUnknownField.FindStringSubmatch(detail); len(uf) >= 2 {
			field := strings.TrimSpace(uf[1])
			hint := hintForUnknownField(field, content)
			if hint != "" {
				appendLine(lineNum, fmt.Sprintf("unsupported field '%s': %s", field, hint))
				return out
			}
			appendLine(lineNum, fmt.Sprintf("unsupported field '%s'", field))
			return out
		}
		appendLine(lineNum, fmt.Sprintf("YAML error: %s", detail))
		return out
	}

	lineNum, _ := extractYamlErrorPosition(msg)
	if uf := reUnknownField.FindStringSubmatch(msg); len(uf) >= 2 {
		field := strings.TrimSpace(uf[1])
		hint := hintForUnknownField(field, content)
		if hint != "" {
			appendLine(lineNum, fmt.Sprintf("unsupported field '%s': %s", field, hint))
			return out
		}
		appendLine(lineNum, fmt.Sprintf("unsupported field '%s'", field))
		return out
	}

	appendLine(lineNum, fmt.Sprintf("YAML error: %v", err))
	return out
}

func hintForUnknownField(field, content string) string {
	lowerField := strings.ToLower(strings.TrimSpace(field))
	if lowerField == "" {
		return ""
	}

	nucleiKeywords := map[string]struct{}{
		"requests":            {},
		"http":                {},
		"tcp":                 {},
		"dns":                 {},
		"ssl":                 {},
		"variables":           {},
		"matchers":            {},
		"matchers-condition":  {},
		"extractors":          {},
		"payloads":            {},
		"attack":              {},
		"stop-at-first-match": {},
		"flow":                {},
		"metadata":            {},
	}

	if _, ok := nucleiKeywords[lowerField]; ok || looksLikeNucleiTemplate(content) {
		switch lowerField {
		case "requests", "http", "tcp", "dns":
			return "looks like nuclei template structure; afrog expects 'rules' + 'expression'"
		case "matchers", "matchers-condition", "extractors":
			return "looks like nuclei matchers/extractors; afrog uses CEL 'expression' and optional 'extractors'"
		default:
			return "looks like nuclei syntax; rewrite with afrog fields"
		}
	}

	if strings.Contains(lowerField, "matcher") || strings.Contains(lowerField, "extractor") {
		return "afrog doesn't support this key; use 'expression' and/or 'extractors'"
	}

	return "afrog doesn't support this key"
}

func looksLikeNucleiTemplate(content string) bool {
	re := regexp.MustCompile(`(?m)^\s*(requests|http|tcp|dns)\s*:\s*$`)
	if re.MatchString(content) {
		return true
	}
	return regexp.MustCompile(`(?m)^\s*matchers(-condition)?\s*:\s*$`).MatchString(content)
}

// extractYamlErrorPosition 从YAML错误信息中提取行号和列号
func extractYamlErrorPosition(errMsg string) (int, int) {
	// 匹配 "line X: ..." 或 "yaml: line X: ..."
	lineRegex := regexp.MustCompile(`line (\d+)`)
	matches := lineRegex.FindStringSubmatch(errMsg)
	if len(matches) >= 2 {
		if line, err := strconv.Atoi(matches[1]); err == nil {
			return line, 0
		}
	}
	return 0, 0
}

// validatePocStructure 验证POC结构
func validatePocStructure(pocData *poc.Poc, filePath string) []ValidationError {
	var errors []ValidationError

	// 必填字段检查
	if pocData.Id == "" {
		errors = append(errors, ValidationError{
			File:    filePath,
			Message: "missing required field: id",
		})
	}

	if pocData.Info.Name == "" {
		errors = append(errors, ValidationError{
			File:    filePath,
			Message: "missing required field: info.name",
		})
	}

	if pocData.Info.Author == "" {
		errors = append(errors, ValidationError{
			File:    filePath,
			Message: "missing required field: info.author",
		})
	}

	// 严重等级验证
	validSeverities := []string{"info", "low", "medium", "high", "critical"}
	if pocData.Info.Severity != "" {
		found := false
		for _, severity := range validSeverities {
			if strings.EqualFold(pocData.Info.Severity, severity) {
				found = true
				break
			}
		}
		if !found {
			errors = append(errors, ValidationError{
				File: filePath,
				Message: fmt.Sprintf("invalid severity '%s', must be one of: %s",
					pocData.Info.Severity, strings.Join(validSeverities, ", ")),
			})
		}
	}

	// 传输协议验证
	if pocData.Transport != "" {
		validTransports := []string{"http", "https", "tcp", "udp", "ssl"}
		found := false
		for _, transport := range validTransports {
			if pocData.Transport == transport {
				found = true
				break
			}
		}
		if !found {
			errors = append(errors, ValidationError{
				File: filePath,
				Message: fmt.Sprintf("invalid transport '%s', must be one of: %s",
					pocData.Transport, strings.Join(validTransports, ", ")),
			})
		}
	}

	if len(pocData.Info.Requires) > 0 {
		mode := strings.ToLower(strings.TrimSpace(pocData.Info.RequiresMode))
		if mode != "" && mode != "strict" && mode != "opportunistic" {
			errors = append(errors, ValidationError{
				File: filePath,
				Message: fmt.Sprintf("invalid requires-mode '%s', must be one of: strict, opportunistic",
					pocData.Info.RequiresMode),
			})
		}
	}

	return errors
}

// validateExpressions 验证表达式
func validateExpressions(pocData *poc.Poc, filePath, content string) []ValidationError {
	var errors []ValidationError

	// 验证主表达式
	if pocData.Expression != "" {
		if errs := validateSingleExpression(pocData.Expression, filePath, content, "main expression"); len(errs) > 0 {
			errors = append(errors, errs...)
		}
	}

	// 验证规则表达式
	for _, rule := range pocData.Rules {
		if rule.Value.Expression != "" {
			if errs := validateSingleExpression(rule.Value.Expression, filePath, content, fmt.Sprintf("rule '%s' expression", rule.Key)); len(errs) > 0 {
				errors = append(errors, errs...)
			}
		}

		// 验证多个表达式
		for i, expr := range rule.Value.Expressions {
			if errs := validateSingleExpression(expr, filePath, content, fmt.Sprintf("rule '%s' expression[%d]", rule.Key, i)); len(errs) > 0 {
				errors = append(errors, errs...)
			}
		}
	}

	return errors
}

// validateSingleExpression 验证单个表达式
// 在 validateSingleExpression 函数中添加新的验证调用
func validateSingleExpression(expression, filePath, content, context string) []ValidationError {
	var errors []ValidationError

	// 移除多余空格
	expr := strings.TrimSpace(expression)
	if expr == "" {
		return errors
	}

	// 获取表达式在文件中的行号
	lineNum := findExpressionLineNumber(content, expression)

	// 验证逻辑操作符前后是否有操作数
	if err := validateLogicalOperators(expr); err != nil {
		errors = append(errors, ValidationError{
			File:    filePath,
			Line:    lineNum,
			Message: fmt.Sprintf("%s error: %v", context, err),
		})
	}

	// 验证response.status使用
	if err := validateResponseStatus(expr); err != nil {
		errors = append(errors, ValidationError{
			File:    filePath,
			Line:    lineNum,
			Message: fmt.Sprintf("%s error: %v", context, err),
		})
	}

	// 验证函数调用语法
	if err := validateFunctionCalls(expr); err != nil {
		errors = append(errors, ValidationError{
			File:    filePath,
			Line:    lineNum,
			Message: fmt.Sprintf("%s error: %v", context, err),
		})
	}

	// 验证response对象属性名称
	if err := validateResponseProperties(expr); err != nil {
		errors = append(errors, ValidationError{
			File:    filePath,
			Line:    lineNum,
			Message: fmt.Sprintf("%s error: %v", context, err),
		})
	}

	return errors
}

// findExpressionLineNumber 查找表达式在文件中的行号
func findExpressionLineNumber(content, expression string) int {
	lines := strings.Split(content, "\n")
	cleanExpr := strings.TrimSpace(expression)

	for i, line := range lines {
		if strings.Contains(line, "expression:") && strings.Contains(line, cleanExpr) {
			return i + 1
		}
		// 处理多行表达式
		if strings.Contains(line, "expression:") {
			// 检查后续几行
			for j := i + 1; j < len(lines) && j < i+5; j++ {
				if strings.Contains(lines[j], cleanExpr) {
					return j + 1
				}
			}
		}
	}
	return 0
}

// validateLogicalOperators 验证逻辑操作符
func validateLogicalOperators(expr string) error {
	// 检查 && 和 || 操作符前后是否有操作数
	logicalOps := []string{"&&", "||"}

	for _, op := range logicalOps {
		if strings.Contains(expr, op) {
			parts := strings.Split(expr, op)
			for _, part := range parts {
				trimmed := strings.TrimSpace(part)
				if trimmed == "" {
					return fmt.Errorf("逻辑操作符 '%s' 前后缺少操作数", op)
				}
				// 检查是否只是括号
				if trimmed == "(" || trimmed == ")" {
					return fmt.Errorf("逻辑操作符 '%s' 附近语法错误", op)
				}
			}
		}
	}

	return nil
}

// validateResponseStatus 验证response.status使用
func validateResponseStatus(expr string) error {
	// 检查response.status的使用
	statusPattern := regexp.MustCompile(`response\.status\s*([=!<>]+)\s*(\d+)`)
	matches := statusPattern.FindAllStringSubmatch(expr, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			operator := strings.TrimSpace(match[1])
			statusCode := strings.TrimSpace(match[2])

			// 验证操作符
			validOps := []string{"==", "!=", ">", "<", ">=", "<="}
			found := false
			for _, op := range validOps {
				if operator == op {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("invalid operator '%s' for response.status", operator)
			}

			// 验证状态码范围
			if len(statusCode) != 3 {
				return fmt.Errorf("invalid HTTP status code '%s', must be 3 digits", statusCode)
			}
		}
	}

	return nil
}

// validateFunctionCalls 验证函数调用
func validateFunctionCalls(expr string) error {
	// CEL内置函数和afrog扩展函数
	validFunctions := []string{
		// CEL内置函数
		"bytes", "string", "int", "uint", "double", "bool", "type",
		"size", "has", "all", "exists", "exists_one", "map", "filter",
		"duration", "timestamp", "getDate", "getDayOfMonth", "getDayOfWeek",
		"getDayOfYear", "getFullYear", "getHours", "getMilliseconds",
		"getMinutes", "getMonth", "getSeconds",

		// afrog扩展函数
		"contains", "icontains", "bcontains", "ibcontains",
		"startsWith", "bstartsWith", "endsWith",
		"matches", "bmatches", "submatch", "bsubmatch",
		"md5", "base64", "base64Decode", "urlencode", "urldecode",
		"toUpper", "toLower", "substr", "replaceAll", "printable",
		"toUintString", "hexdecode", "faviconHash",
		"randomInt", "randomLowercase", "sleep",
		"year", "shortyear", "month", "day", "timestamp_second",
		"versionCompare", "ysoserial", "aesCBC", "repeat", "decimal", "length",
		"oobCheck", "oobCheckToken", "oobEvidence", "wait", "jndi",
	}

	// 先移除字符串字面量，避免误判字符串内容为函数调用
	cleanExpr := removeStringLiterals(expr)

	// 检查函数调用格式
	funcPattern := regexp.MustCompile(`(\w+)\s*\(`)
	matches := funcPattern.FindAllStringSubmatch(cleanExpr, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			funcName := match[1]

			// 跳过规则函数调用 (r0, r1, etc. 和自定义规则名)
			if regexp.MustCompile(`^r\d+$`).MatchString(funcName) {
				continue
			}

			// 跳过可能的自定义规则名（包含字母和数字的组合）
			if regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*$`).MatchString(funcName) {
				// 这可能是自定义规则名，需要在POC结构中验证
				continue
			}

			// 检查是否为有效函数
			found := false
			for _, validFunc := range validFunctions {
				if funcName == validFunc {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("unknown function '%s'", funcName)
			}
		}
	}

	return nil
}

// 新增验证函数
func validateResponseProperties(expr string) error {
	// 先移除字符串字面量，避免误判字符串内容为response属性
	cleanExpr := removeStringLiterals(expr)

	// 检查response对象的属性使用
	responsePattern := regexp.MustCompile(`response\.(\w+)`)
	matches := responsePattern.FindAllStringSubmatch(cleanExpr, -1)

	validProperties := []string{
		"status", "body", "headers", "header", "content_type",
		"raw", "raw_header", "cert", "latency", "url",
	}

	for _, match := range matches {
		if len(match) >= 2 {
			property := match[1]

			// 检查是否为有效属性
			found := false
			for _, validProp := range validProperties {
				if property == validProp {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("invalid response property '%s', valid properties are: %s",
					property, strings.Join(validProperties, ", "))
			}
		}
	}

	return nil
}

// removeStringLiterals 移除表达式中的字符串字面量
func removeStringLiterals(expr string) string {
	// 移除单引号字符串
	singleQuotePattern := regexp.MustCompile(`'[^']*'`)
	expr = singleQuotePattern.ReplaceAllString(expr, "''")

	// 移除双引号字符串
	doubleQuotePattern := regexp.MustCompile(`"[^"]*"`)
	expr = doubleQuotePattern.ReplaceAllString(expr, `""`)

	// 移除字节字符串 b'...' 和 b"..."
	byteStringPattern := regexp.MustCompile(`b'[^']*'|b"[^"]*"`)
	expr = byteStringPattern.ReplaceAllString(expr, "b''")

	return expr
}

func ValidateSinglePocFile(filePath string) error {
	result := validateSinglePocFile(filePath)
	if result.Passed {
		return nil
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("❌ %s: validation failed\n", filePath))
	for _, err := range result.Errors {
		b.WriteString("   ")
		b.WriteString(err.Error())
		b.WriteString("\n")
	}
	return errors.New(strings.TrimSpace(b.String()))
}
