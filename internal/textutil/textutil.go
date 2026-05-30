// Package textutil contains small shared string helpers.
package textutil

import "strings"

// LowerTrim trims surrounding whitespace and lowercases the result.
func LowerTrim(input string) string {
	return strings.ToLower(strings.TrimSpace(input))
}
