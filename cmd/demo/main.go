package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

func main() {
	prefix := ""
	if len(os.Args) > 1 {
		prefix = os.Args[1]
	}

	env := os.Environ()
	slices.Sort(env)

	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		fmt.Println(entry)
	}
}
