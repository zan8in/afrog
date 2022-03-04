package utils

import "strings"

var quotes = []rune{'"', '\'', '`'}

// StringSlice is a slice of strings
type StringSlice []string

// Set appends a value to the string slice.
func (stringSlice *StringSlice) Set(value string) {
	*stringSlice = append(*stringSlice, value)
}

func (stringSlice StringSlice) String() string {
	return ToString(stringSlice)
}

func ToString(slice []string) string {
	defaultBuilder := &strings.Builder{}
	defaultBuilder.WriteString("[")
	for i, k := range slice {
		defaultBuilder.WriteString("\"")
		defaultBuilder.WriteString(k)
		defaultBuilder.WriteString("\"")
		if i != len(slice)-1 {
			defaultBuilder.WriteString(", ")
		}
	}
	defaultBuilder.WriteString("]")
	return defaultBuilder.String()
}

func isEmpty(s string) bool {
	return strings.TrimSpace(s) != ""
}

func normalize(s string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(s), string(quotes)))
}

func normalizeLowercase(s string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(strings.ToLower(s)), string(quotes)))
}
