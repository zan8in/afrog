package raw

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	fileutil "github.com/zan8in/pins/file"
)

const (
	HTTP_PROXY_ENV = "HTTP_PROXY"
	SOCKS5         = "socks5"
	HTTP           = "http"
	HTTPS          = "https"
	DefaultTimeout = 10
)

var (
	// ProxyURL is the URL for the proxy server
	ProxyURL string
	// ProxySocksURL is the URL for the proxy socks server
	ProxySocksURL string
)

var proxyURLList []url.URL

// loadProxyServers load list of proxy servers from file or comma seperated
func LoadProxyServers(proxy string) error {
	if len(proxy) == 0 {
		return nil
	}

	if len(strings.Split(proxy, ",")) > 1 {
		for _, proxy := range strings.Split(proxy, ",") {
			if strings.TrimSpace(proxy) == "" {
				continue
			}
			if proxyURL, err := validateProxyURL(proxy); err != nil {
				return err
			} else {
				proxyURLList = append(proxyURLList, proxyURL)
			}
		}
	} else if proxyURL, err := validateProxyURL(proxy); err == nil {
		proxyURLList = append(proxyURLList, proxyURL)
	} else if fileutil.FileExists(proxy) {
		file, err := os.Open(proxy)
		if err != nil {
			return fmt.Errorf("could not open proxy file: %w", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			proxy := scanner.Text()
			if strings.TrimSpace(proxy) == "" {
				continue
			}
			if proxyURL, err := validateProxyURL(proxy); err != nil {
				return err
			} else {
				proxyURLList = append(proxyURLList, proxyURL)
			}
		}
	} else {
		return fmt.Errorf("invalid proxy file or URL provided for %s", proxy)
	}
	return processProxyList()
}

func processProxyList() error {
    if len(proxyURLList) == 0 {
        return fmt.Errorf("could not find any valid proxy")
    }

    done := make(chan struct{})
    exitCounter := make(chan struct{})
    total := len(proxyURLList)

    for _, p := range proxyURLList {
        go runProxyConnectivity(p, done, exitCounter)
    }

    checked := 0
    for {
        select {
        case <-done:
            return nil
        case <-exitCounter:
            checked++
            if checked == total {
                return errors.New("no reachable proxy found")
            }
        }
    }
}

func runProxyConnectivity(proxyURL url.URL, done chan struct{}, exitCounter chan struct{}) {
    if err := testProxyConnection(proxyURL, DefaultTimeout); err == nil {
        if ProxyURL == "" && ProxySocksURL == "" {
            assignProxyURL(proxyURL)
            done <- struct{}{}
        }
    }
    exitCounter <- struct{}{}
}

func testProxyConnection(proxyURL url.URL, timeoutDelay int) error {
	timeout := time.Duration(timeoutDelay) * time.Second
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", proxyURL.Hostname(), proxyURL.Port()), timeout)
	if err != nil {
		fmt.Println("testproxy error: ", err, proxyURL)
		return err
	}
	return nil
}

func assignProxyURL(proxyURL url.URL) {
	if proxyURL.Scheme == HTTP || proxyURL.Scheme == HTTPS {
		ProxyURL = proxyURL.String()
		ProxySocksURL = ""
	} else if proxyURL.Scheme == SOCKS5 {
		ProxyURL = ""
		ProxySocksURL = proxyURL.String()
	}
}

func validateProxyURL(proxy string) (url.URL, error) {
	if url, err := url.Parse(proxy); err == nil && isSupportedProtocol(url.Scheme) {
		return *url, nil
	}
	return url.URL{}, errors.New("invalid proxy format (It should be http[s]/socks5://[username:password@]host:port), ProxyURL: " + proxy)
}

// isSupportedProtocol checks given protocols are supported
func isSupportedProtocol(value string) bool {
	return value == HTTP || value == HTTPS || value == SOCKS5
}

func RandomIntWithMin(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return int(rand.Intn(max-min) + min)
}
