package gox

import (
	"context"
	"fmt"
	"strings"
	"time"

	urlutil "github.com/zan8in/pins/url"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

func init() {
	funcMap["mongodb-weak-login"] = mongodb_weak_login
}

func mongodb_weak_login(target string, variableMap map[string]any) error {
	variableMap["request"] = nil
	variableMap["response"] = nil

	host, err := resolveMongoDBAddress(target)
	if err != nil {
		return err
	}

	// 1. Check for Unauthorized Access (No Auth required)
	if mongoUnauthAttempt(host) {
		setResponse("success;user=unauthorized;pass=none", variableMap)
		setRequest(host, variableMap)
		setTarget(host, variableMap)
		setFullTarget(host, variableMap)
		return nil
	}

	// 2. Check for Weak Credentials
	usernames := []string{"admin", "root", "user", "test", "mongo", "mongodb"}
	passwords := []string{"123456", "password", "12345678", "admin", "root", "mongo", "mongodb", "test"}

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
			if mongoAuthAttempt(host, u, p) {
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

func resolveMongoDBAddress(target string) (string, error) {
	host, err := urlutil.Host(target)
	if err != nil {
		hostname, herr := urlutil.Hostname(target)
		if herr != nil {
			return "", herr
		}
		return fmt.Sprintf("%s:%d", hostname, 27017), nil
	}
	if !strings.Contains(host, ":") {
		return fmt.Sprintf("%s:%d", host, 27017), nil
	}
	return host, nil
}

// mongoUnauthAttempt tries to list databases without authentication
func mongoUnauthAttempt(host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	uri := fmt.Sprintf("mongodb://%s/?connectTimeoutMS=5000", host)
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return false
	}
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			// handle error if needed, but for POC just ignore
		}
	}()

	// Ping the primary
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return false
	}

	// Try to list databases
	_, err = client.ListDatabaseNames(ctx, map[string]interface{}{})
	return err == nil
}

// mongoAuthAttempt tries to authenticate using SCRAM-SHA-1 or SCRAM-SHA-256 (default)
func mongoAuthAttempt(host, username, password string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try admin database first as it's common for root/admin users
	uri := fmt.Sprintf("mongodb://%s:%s@%s/?connectTimeoutMS=5000&authSource=admin", username, password, host)
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return false
	}
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			// ignore
		}
	}()

	// Ping verify connection and auth
	err = client.Ping(ctx, readpref.Primary())
	return err == nil
}
