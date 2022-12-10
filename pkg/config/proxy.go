package config

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/zan8in/afrog/pkg/utils"
	"github.com/zan8in/fileutil"
	"github.com/zan8in/gologger"
)

const (
	HTTP_PROXY_ENV = "HTTP_PROXY"
	SOCKS5         = "socks5"
	HTTP           = "http"
	HTTPS          = "https"
)

var (
	// ProxyURL is the URL for the proxy server
	ProxyURL string
	// ProxySocksURL is the URL for the proxy socks server
	ProxySocksURL string
)

var proxyURLList []url.URL

// loadProxyServers load list of proxy servers from file or comma seperated
func LoadProxyServers(options *Options) error {
	if len(options.Proxy) == 0 {
		return nil
	}

	if len(strings.Split(options.Proxy, ",")) > 1 {
		for _, proxy := range strings.Split(options.Proxy, ",") {
			if strings.TrimSpace(proxy) == "" {
				continue
			}
			if proxyURL, err := validateProxyURL(proxy); err != nil {
				return err
			} else {
				proxyURLList = append(proxyURLList, proxyURL)
			}
		}
	} else if proxyURL, err := validateProxyURL(options.Proxy); err == nil {
		proxyURLList = append(proxyURLList, proxyURL)
	} else if fileutil.FileExists(options.Proxy) {
		file, err := os.Open(options.Proxy)
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
		return fmt.Errorf("invalid proxy file or URL provided for %s", options.Proxy)
	}
	return processProxyList(options)
}

func processProxyList(options *Options) error {
	if len(proxyURLList) == 0 {
		return fmt.Errorf("could not find any valid proxy")
	} else {
		done := make(chan bool)
		exitCounter := make(chan bool)
		counter := 0
		// defer close(done)
		// defer close(exitCounter)

		if len(proxyURLList) > 0 {
			i := utils.GetRandomIntWithMin(0, len(proxyURLList))
			go runProxyConnectivity(proxyURLList[i], options, done, exitCounter)

			for {
				select {
				case <-done:
					{
						close(done)
						return nil
					}
				case <-exitCounter:
					{
						if counter += 1; counter == len(proxyURLList) {
							return errors.New("no reachable proxy found")
						}
						close(exitCounter)
					}
				}
			}
		}
	}
	return nil
}

func runProxyConnectivity(proxyURL url.URL, options *Options, done chan bool, exitCounter chan bool) {
	fmt.Println(proxyURL)
	if err := testProxyConnection(proxyURL, options.Timeout); err == nil {
		if ProxyURL == "" && ProxySocksURL == "" {
			assignProxyURL(proxyURL, options)
			done <- true
		}
	}
	exitCounter <- true
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

func assignProxyURL(proxyURL url.URL, options *Options) {
	// if options.ProxyInternal {
	// 	os.Setenv(HTTP_PROXY_ENV, proxyURL.String())
	// }
	if proxyURL.Scheme == HTTP || proxyURL.Scheme == HTTPS {
		ProxyURL = proxyURL.String()
		ProxySocksURL = ""
		gologger.Verbose().Msgf("Using %s as proxy server", proxyURL.String())
	} else if proxyURL.Scheme == SOCKS5 {
		ProxyURL = ""
		ProxySocksURL = proxyURL.String()
		gologger.Verbose().Msgf("Using %s as socket proxy server", proxyURL.String())
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
