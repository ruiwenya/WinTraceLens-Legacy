//go:build windows

package main

import "testing"

func TestFilterRowsRegex(t *testing.T) {
	rows := [][]string{
		{"DNS", "www.bandisoft.com", "192.168.111.173"},
		{"DNS", "example.net", "10.0.0.5"},
	}

	matched := filterRows(rows, `/www\..*\.com/i`)
	if len(matched) != 1 || matched[0][1] != "www.bandisoft.com" {
		t.Fatalf("domain regex mismatch: %#v", matched)
	}

	matched = filterRows(rows, `/192\.\d+\.\d+\.173/`)
	if len(matched) != 1 || matched[0][2] != "192.168.111.173" {
		t.Fatalf("IP regex mismatch: %#v", matched)
	}
}

func TestFilterRowsInvalidRegexFallsBackToLiteral(t *testing.T) {
	rows := [][]string{{"process", "chrome.exe"}}
	matched := filterRows(rows, `/chrome[.exe/i`)
	if len(matched) != 0 {
		t.Fatalf("invalid regex should use literal matching: %#v", matched)
	}
}
