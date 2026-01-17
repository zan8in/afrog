package gox

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["mssql-weak-login"] = mssql_weak_login
}

func mssql_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveMSSQLAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"sa", "admin", "administrator", "web", "test", "mssql"}
	passwords := []string{"123456", "password", "12345678", "sa", "admin", "mssql", "test", "12345", "Aa123456"}

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
			if mssqlAuthAttempt(host, u, p) {
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

func resolveMSSQLAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 1433), nil
	}
	if !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, 1433), nil
	}
	return host, nil
}

func mssqlAuthAttempt(host, username, password string) bool {
	// Construct connection string
	// server=%s;user id=%s;password=%s;encrypt=disable;connection timeout=5
	query := url.Values{}
	query.Add("encrypt", "disable")
	query.Add("connection timeout", "5") // 5s connection timeout

	u := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(username, password),
		Host:     host,
		RawQuery: query.Encode(),
	}

	db, err := sql.Open("sqlserver", u.String())
	if err != nil {
		return false
	}
	defer db.Close()

	// Set a global context timeout for the Ping operation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use PingContext to enforce timeout
	err = db.PingContext(ctx)
	return err == nil
}
