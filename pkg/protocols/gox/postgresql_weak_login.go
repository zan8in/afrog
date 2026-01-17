package gox

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
	urlutil "github.com/zan8in/pins/url"
)

func init() {
	funcMap["postgresql-weak-login"] = postgresql_weak_login
}

func postgresql_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolvePostgreSQLAddress(target)
	if err != nil {
		return err
	}

	usernames := []string{"postgres", "admin", "root", "test", "user", "pgsql"}
	passwords := []string{"postgres", "123456", "password", "12345678", "admin", "root", "test", "12345", "pgsql"}
	// Common databases to try
	databases := []string{"postgres", "template1"}

	maxTries := 200
	if v := variableMap["max_tries"]; v != nil {
		if n, ok := v.(int); ok && n > 0 {
			maxTries = n
		}
	}

	tried := 0
	for _, u := range usernames {
		for _, p := range passwords {
			for _, db := range databases {
				if maxTries > 0 && tried >= maxTries {
					setResponse(fmt.Sprintf("fail;reason=max_tries;tried=%d", tried), variableMap)
					setRequest(host, variableMap)
					setTarget(host, variableMap)
					setFullTarget(host, variableMap)
					return nil
				}
				tried++
				if postgresAuthAttempt(host, db, u, p) {
					setResponse(fmt.Sprintf("success;user=%s;pass=%s;db=%s", u, p, db), variableMap)
					setRequest(host, variableMap)
					setTarget(host, variableMap)
					setFullTarget(host, variableMap)
					return nil
				}
			}
		}
	}

	setResponse(fmt.Sprintf("fail;reason=not_found;tried=%d", tried), variableMap)
	setRequest(host, variableMap)
	setTarget(host, variableMap)
	setFullTarget(host, variableMap)
	return nil
}

func resolvePostgreSQLAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 5432), nil
	}
	if !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, 5432), nil
	}
	return host, nil
}

func postgresAuthAttempt(host, dbName, username, password string) bool {
	// Build connection string
	// postgres://user:password@host:port/dbname?sslmode=disable&connect_timeout=5
	connStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable&connect_timeout=5",
		username, password, host, dbName)

	db, err := sql.Open("postgres", connStr)
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
