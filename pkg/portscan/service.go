package portscan

import (
	"regexp"
	"strings"
)

// IdentifyService tries to identify the service based on the banner
func IdentifyService(banner string, port int) *ServiceFingerprint {
	if banner == "" {
		return guessServiceByPort(port)
	}

	banner = strings.ToLower(banner)

	// Basic matching logic (this should be expanded or loaded from a file)
	if strings.Contains(banner, "ssh") {
		return &ServiceFingerprint{Name: "ssh", Version: extractVersion(banner, "ssh")}
	}
	if strings.Contains(banner, "ftp") {
		return &ServiceFingerprint{Name: "ftp", Version: extractVersion(banner, "ftp")}
	}
	if strings.Contains(banner, "mysql") {
		return &ServiceFingerprint{Name: "mysql", Version: extractVersion(banner, "ver")}
	}
	if strings.Contains(banner, "redis") {
		return &ServiceFingerprint{Name: "redis", Version: extractVersion(banner, "redis")}
	}
	if strings.Contains(banner, "smtp") || strings.Contains(banner, "esmtp") {
		return &ServiceFingerprint{Name: "smtp"}
	}
	if strings.Contains(banner, "http") || strings.Contains(banner, "html") {
		return &ServiceFingerprint{Name: "http"}
	}

	return guessServiceByPort(port)
}

func guessServiceByPort(port int) *ServiceFingerprint {
	switch port {
	case 80, 8080, 8000:
		return &ServiceFingerprint{Name: "http"}
	case 443, 8443:
		return &ServiceFingerprint{Name: "https"}
	case 21:
		return &ServiceFingerprint{Name: "ftp"}
	case 22:
		return &ServiceFingerprint{Name: "ssh"}
	case 23:
		return &ServiceFingerprint{Name: "telnet"}
	case 25:
		return &ServiceFingerprint{Name: "smtp"}
	case 53:
		return &ServiceFingerprint{Name: "dns"}
	case 3306:
		return &ServiceFingerprint{Name: "mysql"}
	case 5432:
		return &ServiceFingerprint{Name: "postgresql"}
	case 6379:
		return &ServiceFingerprint{Name: "redis"}
	case 27017:
		return &ServiceFingerprint{Name: "mongodb"}
	case 3389:
		return &ServiceFingerprint{Name: "rdp"}
	case 445:
		return &ServiceFingerprint{Name: "smb"}
	default:
		return &ServiceFingerprint{Name: "unknown"}
	}
}

func extractVersion(banner, key string) string {
	// Simple regex to extract version
	// e.g., "OpenSSH_7.6p1" -> "7.6p1"
	re := regexp.MustCompile(key + `[ _/]?(\d+(\.\d+)+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
