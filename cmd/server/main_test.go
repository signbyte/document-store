package main

import "testing"

// TestVersionDefault is a minimal smoke test for the main package: building a
// test binary for it runs the health/web command registrations in this
// package's init() functions (CLI wiring only — actually running the server
// is exercised by team-hound's E2E harness, not a Go unit test).
func TestVersionDefault(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
}
