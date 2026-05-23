package agent

import (
	"os"
	"strings"
)

func SnippetAround(path string, line, radius int) string {
	if radius <= 0 {
		radius = 10
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return ""
	}
	if line <= 0 {
		line = 1
	}
	start := line - radius
	if start < 1 {
		start = 1
	}
	end := line + radius
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		b.WriteString(lines[i-1])
		b.WriteString("\n")
	}
	return b.String()
}
