package utils

import (
	"log"
	"strconv"
	"strings"
)

// reference : https://github.com/michelia/uversion/blob/a1caf6fb6aad0a4e92b2c51e097f33518e2ff8da/version_compare.go

// vCompareSlice operator为 < <= > >= = ==
func vCompareSlice(v1s []string, operator string, v2s []string) bool {
	switch operator {
	case "<", "<=", ">", ">=", "==":
	default:
		log.Print("不合法的比较符")
		return false
	}
	l := len(v1s)
	switch {
	case len(v1s) > len(v2s):
		l = len(v1s)
		diff := len(v1s) - len(v2s)
		for i := 0; i < diff; i++ {
			v2s = append(v2s, "0")
		}
	case len(v1s) < len(v2s):
		l = len(v2s)
		diff := len(v2s) - len(v1s)
		for i := 0; i < diff; i++ {
			v1s = append(v1s, "0")
		}
	}
	switch operator {
	case "==":
		if strings.Join(v1s, ".") == strings.Join(v2s, ".") {
			return true
		} else {
			return false
		}
	case ">=", "<=":
		operator = string(operator[0]) // 只取 < 或 >
		// 因为 operator 包含 =
		if strings.Join(v1s, ".") == strings.Join(v2s, ".") {
			return true
		}
	}

	for i := 0; i < l; i++ {
		fs := false // fs flag string 表示是字符, 不能转化为int
		n1, err := strconv.Atoi(v1s[i])
		if err != nil {
			fs = true
		}
		n2, err := strconv.Atoi(v2s[i])
		if err != nil {
			fs = true
		}
		switch operator {
		case "<":
			if fs {
				switch {
				case v1s[i] == v2s[i]:
					continue
				case v1s[i] < v2s[i]:
					return true
				case v1s[i] > v2s[i]:
					return false
				}
			} else {
				switch {
				case n1 == n2:
					continue
				case n1 < n2:
					return true
				case n1 > n2:
					return false
				}
			}
		case ">":
			if fs {
				switch {
				case v1s[i] == v2s[i]:
					continue
				case v1s[i] > v2s[i]:
					return true
				case v1s[i] < v2s[i]:
					return false
				}
			} else {
				switch {
				case n1 == n2:
					continue
				case n1 > n2:
					return true
				case n1 < n2:
					return false
				}
			}
		}
	}
	return false
}

// Compare operator为 < <= > >= ==
func Compare(v1, operator, v2 string) bool {
	if len(v1) == 0 || len(v2) == 0 || len(operator) == 0 {
		return false
	}
	v1s := strings.Split(v1, ".")
	v2s := strings.Split(v2, ".")
	return vCompareSlice(v1s, operator, v2s)
}

// Between operator为 < <= > >= ==
func Between(v1, o1, v, o2, v2 string) bool {
	v1s := strings.Split(v1, ".")
	vs := strings.Split(v, ".")
	v2s := strings.Split(v2, ".")
	if vCompareSlice(v1s, o1, vs) && vCompareSlice(vs, o2, v2s) {
		return true
	}
	return false
}
