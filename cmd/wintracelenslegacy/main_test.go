//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/history"
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

func TestHistoryViewsSeparateDNSAndRetainSYN(t *testing.T) {
	records := []history.Record{
		{Source: "DNS 缓存", Query: "www.example.com", Details: "ipconfig /displaydns"},
		{Time: "2026-09-16 10:30:00", Source: "安全日志 WFP", PID: "3996", Process: `C:\ProgramData\sample.exe`, Proto: "TCP", Remote: "203.0.113.8:445", Action: "允许"},
	}
	dnsRows := historyDNSDisplayRows(records)
	if len(dnsRows) != 1 || len(dnsRows[0]) != len(historyDNSColumns) || dnsRows[0][1] != "www.example.com" {
		t.Fatalf("unexpected DNS rows: %#v", dnsRows)
	}
	connectionRows := historyConnectionDisplayRows(records)
	if len(connectionRows) != 1 || connectionRows[0][4] != "203.0.113.8:445" {
		t.Fatalf("unexpected connection rows: %#v", connectionRows)
	}
	monitorRows := historyMonitorDisplayRows([]history.ObservedConnection{{
		PID: 3996, Process: "sample.exe", Protocol: "TCP4", State: "SYN-SENT",
		Local: "192.168.1.20:51000", Remote: "203.0.113.8:445",
		FirstSeen: "2026-09-16 10:30:00", LastSeen: "2026-09-16 10:30:01",
		Occurrences: 1, Samples: 2,
	}})
	if len(monitorRows) != 1 || !strings.Contains(monitorRows[0][3], "SYN-SENT") || monitorRows[0][6] != "1 / 2" {
		t.Fatalf("unexpected monitor rows: %#v", monitorRows)
	}
}

func TestHistoryConnectionViewExplainsUnavailableLogs(t *testing.T) {
	rows := historyConnectionDisplayRows(nil)
	if len(rows) != 1 || rows[0][1] != "采集说明" || !strings.Contains(rows[0][6], "Sysmon") || !strings.Contains(rows[0][6], "5156/5157") {
		t.Fatalf("missing connection history guidance: %#v", rows)
	}
}

func TestCurrentSessionEvidenceIncludesShortConnections(t *testing.T) {
	snapshot := legacyEvidenceSnapshot{
		CapturedAt: "2026-09-16 10:30:00",
		HistoryMonitor: [][]string{{
			"2026-09-16 10:30:00", "2026-09-16 10:30:01", "sample.exe (PID 3996)", "TCP4 / SYN-SENT",
			"192.168.1.20:51000", "203.0.113.8:445", "1 / 2", "否", `C:\ProgramData\sample.exe`, "公网/外部",
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
	found := false
	for _, file := range reader.File {
		if file.Name != "current-session/network-short-connections.csv" {
			continue
		}
		stream, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			t.Fatal(err)
		}
		found = strings.Contains(string(data), "SYN-SENT") && strings.Contains(string(data), "203.0.113.8:445")
	}
	if !found {
		t.Fatal("short connection evidence CSV missing or incomplete")
	}
}
