//go:build windows

package history

import (
	"strings"
	"testing"

	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func TestLimitHistoryRecordsKeepsMultipleSources(t *testing.T) {
	var records []Record
	for i := 0; i < 20; i++ {
		records = append(records, Record{Time: "2026-09-05 12:00:00", Source: "Sysmon", PID: "1"})
	}
	records = append(records,
		Record{Time: "2026-09-05 11:00:00", Source: "安全日志 WFP"},
		Record{Source: "DNS 缓存", Query: "example.test"},
	)
	got, warnings := limitHistoryRecordsBySource(records, 6)
	sources := make(map[string]bool)
	for _, record := range got {
		sources[record.Source] = true
	}
	if len(got) != 6 || !sources["Sysmon"] || !sources["安全日志 WFP"] || !sources["DNS 缓存"] {
		t.Fatalf("source starvation: %#v", got)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "受总上限影响") {
		t.Fatalf("missing truncation warning: %#v", warnings)
	}
}

func TestEnrichNetstatProcessDetails(t *testing.T) {
	records := []Record{
		{Source: "netstat 快照", PID: "4321", Details: "TCP 127.0.0.1:1 127.0.0.1:2 ESTABLISHED 4321"},
		{Source: "DNS 缓存", PID: "4321", Process: "keep"},
	}
	identities := map[uint32]process.Identity{
		4321: {Name: "sample.exe", Path: `C:\Program Files\Sample\sample.exe`},
	}

	enrichNetstatProcessDetailsFromMap(records, identities)

	if records[0].Process != `C:\Program Files\Sample\sample.exe` {
		t.Fatalf("unexpected process display: %q", records[0].Process)
	}
	if !strings.Contains(records[0].Details, "进程名=sample.exe") || !strings.Contains(records[0].Details, `进程路径=C:\Program Files\Sample\sample.exe`) {
		t.Fatalf("missing process identity details: %q", records[0].Details)
	}
	if records[1].Process != "keep" {
		t.Fatalf("non-netstat record was modified: %#v", records[1])
	}
}

func TestDecodeCommandOutputUsesChineseWindowsCodePage(t *testing.T) {
	raw := []byte{0xb2, 0xe9, 0xd1, 0xaf, 0xca, 0xa7, 0xb0, 0xdc}
	got, ok := decodeWindowsCodePage(raw, 936)
	if !ok || got != "查询失败" {
		t.Fatalf("unexpected decoded output: %q", got)
	}
}

func TestLocalizeSysmonQueryFailure(t *testing.T) {
	items := localizeHistoryErrors([]string{"Sysmon: wevtutil 查询失败: 查询失败"})
	if len(items) != 1 || !strings.Contains(items[0], "Sysmon: 查询失败") || !strings.Contains(items[0], "查询失败") {
		t.Fatalf("unexpected localized error: %#v", items)
	}
}
