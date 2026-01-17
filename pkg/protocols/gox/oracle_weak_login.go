package gox

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["oracle-weak-login"] = oracle_weak_login
}

func oracle_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, port, err := resolveOracleAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"system", "sys", "scott", "dbsnmp", "oracle", "admin", "weblogic"}
	passwords := []string{"oracle", "manager", "tiger", "dbsnmp", "system", "change_on_install", "welcome1", "123456", "password"}
	// Common Service Names/SIDs to try if not provided
	serviceNames := []string{"ORCL", "XE", "ORACLE", "DB11G"}

	maxTries := 200
	if v := variableMap["max_tries"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			maxTries = n
		}
	}

	tried := 0
	for _, u := range usernames {
		for _, p := range passwords {
			for _, service := range serviceNames {
				if maxTries > 0 && tried >= maxTries {
					setResponse(fmt.Sprintf("fail;reason=max_tries;tried=%d", tried), variableMap)
					setRequest(fmt.Sprintf("%s:%d", host, port), variableMap)
					setTarget(fmt.Sprintf("%s:%d", host, port), variableMap)
					setFullTarget(fmt.Sprintf("%s:%d", host, port), variableMap)
					return nil
				}
				tried++
				if oracleAuthAttempt(host, port, service, u, p) {
					setResponse(fmt.Sprintf("success;user=%s;pass=%s;service=%s", u, p, service), variableMap)
					setRequest(fmt.Sprintf("%s:%d", host, port), variableMap)
					setTarget(fmt.Sprintf("%s:%d", host, port), variableMap)
					setFullTarget(fmt.Sprintf("%s:%d", host, port), variableMap)
					return nil
				}
			}
		}
	}

	setResponse(fmt.Sprintf("fail;reason=not_found;tried=%d", tried), variableMap)
	setRequest(fmt.Sprintf("%s:%d", host, port), variableMap)
	setTarget(fmt.Sprintf("%s:%d", host, port), variableMap)
	setFullTarget(fmt.Sprintf("%s:%d", host, port), variableMap)
	return nil
}

func resolveOracleAddress(target string) (string, int, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", 0, herr
		}
		return hostname, 1521, nil
	}

	if !strings.Contains(host, ":") {
		return host, 1521, nil
	}

	h, p, err := parseHostPort(host)
	if err != nil {
		return "", 0, err
	}
	portInt := 1521
	fmt.Sscanf(p, "%d", &portInt)
	return h, portInt, nil
}

func oracleAuthAttempt(host string, port int, service, username, password string) bool {
	// Build connection string manually using go-ora builder
	// oracle://user:pass@host:port/service_name
	urlOptions := map[string]string{
		"CONNECTION TIMEOUT": "5", // 5s connection timeout
	}

	connStr := go_ora.BuildUrl(host, port, service, username, password, urlOptions)

	db, err := sql.Open("oracle", connStr)
	if err != nil {
		return false
	}
	defer db.Close()

	// Set a global context timeout for the Ping operation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	return err == nil
}

// parseHostPort handles parsing host:port strings
func parseHostPort(hostport string) (string, string, error) {
	// If it's just a port (e.g., ":8080"), add localhost
	if strings.HasPrefix(hostport, ":") {
		return "localhost", hostport[1:], nil
	}

	// Split from right to handle IPv6 (not perfect but sufficient for most cases)
	lastColon := strings.LastIndex(hostport, ":")
	if lastColon == -1 {
		return hostport, "", nil
	}

	return hostport[:lastColon], hostport[lastColon+1:], nil
}
