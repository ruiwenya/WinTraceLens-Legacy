//go:build windows

package main

import "testing"

func TestDesiredDetailExpanded(t *testing.T) {
	tests := []struct {
		name       string
		preference detailPreference
		selected   bool
		available  int
		want       bool
	}{
		{"initial empty", detailAutomatic, false, 800, false},
		{"automatic enough rows", detailAutomatic, true, 184 + 29 + 8*26 + 4, true},
		{"automatic one pixel short", detailAutomatic, true, 184 + 29 + 8*26 + 3, false},
		{"user closed survives resize", detailUserClosed, true, 1000, false},
		{"user open survives small window", detailUserOpen, true, 240, true},
		{"user open without selection", detailUserOpen, false, 240, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := desiredDetailExpanded(test.preference, test.selected, test.available, 184, 29, 26, 4, 8)
			if got != test.want {
				t.Fatalf("expanded = %v, want %v", got, test.want)
			}
		})
	}
	if !desiredDetailExpanded(detailAutomatic, true, 184+27+8*22+4, 184, 27, 22, 4, 8) {
		t.Fatal("compact density should use its own row and header heights")
	}
}
