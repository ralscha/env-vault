package main

import "testing"

func TestHelpSucceedsWithoutOpeningVault(t *testing.T) {
	if err := run([]string{"--help"}); err != nil {
		t.Fatalf("help: %v", err)
	}
}
