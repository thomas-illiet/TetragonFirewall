package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestValidate verifies successful and rejected SVG documents.
func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"valid", `<svg aria-labelledby="title desc"><title id="title">Title</title><desc id="desc">Description</desc></svg>`, false},
		{"wrong root", `<html></html>`, true},
		{"missing accessibility", `<svg></svg>`, true},
		{"malformed", `<svg>`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "diagram.svg")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			err := validate(path)
			if (err != nil) != test.wantErr {
				t.Fatalf("validate() error=%v, wantErr=%v", err, test.wantErr)
			}
		})
	}
	if err := validate(filepath.Join(t.TempDir(), "missing.svg")); err == nil {
		t.Fatal("expected missing file error")
	}
}
