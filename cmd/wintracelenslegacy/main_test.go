//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

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

func TestEventListIsCompactButDetailsAndExportStayComplete(t *testing.T) {
	longCommand := strings.Repeat("PowerShell-Command ", 80)
	longMessage := strings.Repeat("完整事件消息", 160)
	item := securitylog.Event{
		Time: "2026-09-05 12:00:00", Category: "PowerShell日志", EventID: "4104",
		Command: longCommand, Message: longMessage, Details: "原始详情\r\n第二行",
	}
	rows := eventRows([]securitylog.Event{item})
	if len(rows) != 1 || len(rows[0]) != len(eventColumns)+1 {
		t.Fatalf("event row identity missing: %#v", rows)
	}
	if len([]rune(rows[0][9])) > 365 {
		t.Fatalf("list command was not compacted: %d", len([]rune(rows[0][9])))
	}
	exported := eventExportRows(rows, []securitylog.Event{item})
	if len(exported) != 1 || len(exported[0]) != len(eventExportHeaders) || exported[0][15] != longCommand || exported[0][22] != longMessage || exported[0][23] != item.Details {
		t.Fatal("event export lost original command or message")
	}
	detail := eventDetailText(item)
	if !strings.Contains(detail, longCommand) || !strings.Contains(detail, longMessage) || !strings.Contains(detail, "第二行") {
		t.Fatal("event detail lost original text")
	}
}

func TestCurrentSessionEvidenceIncludesFullEventsAndCoverage(t *testing.T) {
	longCommand := strings.Repeat("命令内容 ", 500)
	snapshot := legacyEvidenceSnapshot{
		CapturedAt: "2026-09-05 12:00:00",
		Processes:  [][]string{{"120", "agent.exe"}},
		Events: []securitylog.Event{{
			Time: "2026-09-05 12:00:00", Category: "PowerShell日志", EventID: "4104", Command: longCommand,
		}},
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	if err := writeCurrentSessionEvidence(writer, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string)
	for _, file := range reader.File {
		stream, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[file.Name] = string(data)
	}
	if !strings.Contains(files["current-session/security-events.csv"], longCommand) {
		t.Fatal("current session event was truncated")
	}
	if !strings.Contains(files["current-session/coverage.csv"], "本次运行未采集") {
		t.Fatal("coverage does not identify unavailable datasets")
	}
}
