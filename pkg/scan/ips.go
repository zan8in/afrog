package scan

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func Target2ip(target string) (string, error) {
	// Just ip
	if IsIPv4(target) {
		return target, nil
	}
	// URL -> Domain -> ip
	if IsURL(target) {
		host, err := URL2host(target)
		if err != nil {
			return "", err
		}
		ip, err := Host2ip(host)
		if err != nil {
			return "", err
		}
		return ip, nil
	}
	// Domain -> ip
	ip, err := Host2ip(target)
	if err != nil {
		return "", err
	}
	return ip, nil
}

func IsURL(target string) bool {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return true
	}
	return false
}

func URL2host(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}

func Host2ip(target string) (string, error) {
	if !IsIP(target) {
		addr, err := Domain2Ip(target)
		if err != nil {
			return "", err
		}
		return addr, nil
	} else {
		return target, nil
	}
}

// IsIP checks if a string is either IP version 4 or 6. Alias for `net.ParseIP`
func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}

// IsPort checks if a string represents a valid port
func IsPort(str string) bool {
	if i, err := strconv.Atoi(str); err == nil && i > 0 && i < 65536 {
		return true
	}
	return false
}

// IsIPv4 checks if the string is an IP version 4.
func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

// IsIPv6 checks if the string is an IP version 6.
func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

func Domain2Ip(domain string) (string, error) {
	if len(domain) == 0 {
		return "", errors.New("domain is empty")
	}
	addr, err := net.ResolveIPAddr("ip", domain)
	if err != nil {
		return "", err
	}
	return addr.IP.String(), nil
}

// IsCIDR checks if the string is an valid CIDR notiation (IPV4 & IPV6)
func IsCIDR(str string) bool {
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

// IsCIDR checks if the string is an valid CIDR after replacing - with /
func IsCidrWithExpansion(str string) bool {
	str = strings.ReplaceAll(str, "-", "/")
	return IsCIDR(str)
}

// ToCidr converts a cidr string to net.IPNet pointer
func ToCidr(item string) *net.IPNet {
	if IsIP(item) {
		item += "/32"
	}
	if IsCIDR(item) {
		_, ipnet, _ := net.ParseCIDR(item)
		return ipnet
	}
	return nil
}

// WhatsMyIP attempts to obtain the external ip through public api
// Copied from https://github.com/projectdiscovery/naabu/blob/master/v2/pkg/scan/externalip.go
func WhatsMyIP() (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.ipify.org?format=text", nil)
	if err != nil {
		return "", nil
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error fetching ip: %s", resp.Status)
	}

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}
