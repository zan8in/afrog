package gox

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "gitee.com/chunanyong/dm"
	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["dameng-weak-login"] = dameng_weak_login
}

func dameng_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveDamengAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"SYSDBA", "SYSAUDITOR", "SYSSSO", "SYS", "admin"}
	passwords := []string{"SYSDBA", "SYSDBA888", "123456789", "dameng123", "123456", "admin123", "dameng", "Dameng@123", "12345678", "password"}

	maxTries := 200
	if v := variableMap["max_tries"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			maxTries = n
		}
	}

	tried := 0
	for _, u := range usernames {
		for _, p := range passwords {
			if maxTries > 0 && tried >= maxTries {
				setResponse(fmt.Sprintf("fail;reason=max_tries;tried=%d", tried), variableMap)
				setRequest(host, variableMap)
				setTarget(host, variableMap)
				setFullTarget(host, variableMap)
				return nil
			}
			tried++
			if damengAuthAttempt(host, u, p) {
				setResponse(fmt.Sprintf("success;user=%s;pass=%s", u, p), variableMap)
				setRequest(host, variableMap)
				setTarget(host, variableMap)
				setFullTarget(host, variableMap)
				return nil
			}
		}
	}

	setResponse(fmt.Sprintf("fail;reason=not_found;tried=%d", tried), variableMap)
	setRequest(host, variableMap)
	setTarget(host, variableMap)
	setFullTarget(host, variableMap)
	return nil
}

func damengAuthAttempt(host, username, password string) bool {
	dsn := fmt.Sprintf("dm://%s:%s@%s?connectTimeout=5000", username, password, host)
	db, err := sql.Open("dm", dsn)
	if err != nil {
		return false
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	return err == nil
}

func resolveDamengAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 5236), nil
	}
	if !hasPort(host) {
		return fmt.Sprintf("%s:%d", host, 5236), nil
	}
	return host, nil
}
