//go:build windows

package main

import (
	"archive/zip"
	"bytes"
	"github.com/lxn/walk"
	"github.com/lxn/win"
	"github.com/ruiwenya/WinTraceLens/internal/commandchain"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"
)

func TestCompactPersistenceDetailsRetainPayloadAndRawEvent(t *testing.T) {
	chain := &commandchain.Chain{Launcher: commandchain.Target{Path: `C:\Windows\System32\cmd.exe`, MD5: "launcher-only", Signature: "系统文件"}, Payloads: []commandchain.Target{{Kind: "file", Path: `C:\CustomRoot\missing.bin`, FileStatus: "文件不存在"}}, Asynchronous: true}
	machine := host.Snapshot{Services: []host.ServiceInfo{{Name: "fixture", Command: "cmd /c start fixture.bin", State: "Stopped", StateNotice: "Stopped 不能证明载荷退出", RiskLevel: "高", RiskScore: 9, ExecutionChain: chain}}, MatchedEvents: []securitylog.PreservedEvent{{ServiceName: "fixture", RecordID: "9876", EventID: "7045", XML: `<Event>完整原始记录</Event>`}}}
	rows := hostRowsFromServices(serviceRowsWithEvidence(machine))
	if len(rows) != 1 || len(rows[0]) != len(hostColumns) {
		t.Fatalf("row/column mismatch: %+v", rows)
	}
	if rows[0][4] != "" || rows[0][5] == "系统文件" || rows[0][6] != chain.Payloads[0].Path {
		t.Fatal("missing child inherited launcher identity")
	}
	detail := fullRowDetail(headersOf(hostColumns), rows[0])
	for _, field := range []string{"launcher-only", chain.Payloads[0].Path, "文件不存在", "9876", "完整原始记录", "Stopped 不能证明"} {
		if !strings.Contains(detail, field) {
			t.Fatalf("detail omits %s", field)
		}
	}
	if len(filterRows(rows, "9876")) != 1 {
		t.Fatal("search ignores hidden evidence")
	}
	for _, columns := range [][]tableColumn{hostColumns, findingColumns} {
		total := 0
		for _, column := range columns {
			if column.Width > 0 {
				total += column.Width
			}
		}
		if total > 900 {
			t.Fatalf("compact view too wide: %d", total)
		}
	}
	if !strings.Contains(fullRowDetail([]string{"详情"}, []string{"真实详情内容"}), "真实详情内容") {
		t.Fatal("actual detail field removed")
	}
}

func TestPersistenceExportRetainsCurrentSessionRawEvent(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	snapshot := legacyEvidenceSnapshot{HostData: host.Snapshot{MatchedEvents: []securitylog.PreservedEvent{{RecordID: "9876", XML: `<Event>完整证据</Event>`}}}}
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
		if file.Name != "current-session/matched-service-events.csv" {
			continue
		}
		stream, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(stream)
		stream.Close()
		if err != nil {
			t.Fatal(err)
		}
		found = bytes.Contains(raw, []byte("完整证据")) && bytes.Contains(raw, []byte("9876"))
	}
	if !found {
		t.Fatal("referenced service event lost from current-session export")
	}
}

func TestNativeDetailCellNotification(t *testing.T) {
	if os.Getenv("WTL_NATIVE_UI_SMOKE") != "1" {
		t.Skip("explicit hidden-window native control smoke test")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	window, err := walk.NewMainWindow()
	if err != nil {
		t.Fatal(err)
	}
	defer window.Dispose()
	view, err := walk.NewTableView(window)
	if err != nil {
		t.Fatal(err)
	}
	model := newTableModel(findingColumns)
	model.SetRows([][]string{{"高", "服务", "fixture", "reason", "hash", "", "hidden path", "command", "raw evidence", "查看详情"}})
	for _, spec := range findingColumns {
		column := walk.NewTableViewColumn()
		column.SetTitle(spec.Title)
		if err := view.Columns().Add(column); err != nil {
			t.Fatal(err)
		}
		if spec.Width < 0 {
			column.SetVisible(false)
		}
	}
	if err := view.SetModel(model); err != nil {
		t.Fatal(err)
	}
	rowIndex, columnIndex := -1, -1
	view.CellClicked().Attach(func(row, column int) {
		if column >= 0 {
			rowIndex, columnIndex = row, column
		}
	})
	visibleCount := 0
	for _, column := range findingColumns {
		if column.Width > 0 {
			visibleCount++
		}
	}
	for child := win.GetWindow(view.Handle(), win.GW_CHILD); child != 0; child = win.GetWindow(child, win.GW_HWNDNEXT) {
		notice := win.NMITEMACTIVATE{Hdr: win.NMHDR{HwndFrom: child, Code: win.NM_CLICK}, IItem: 0, ISubItem: int32(visibleCount - 1)}
		win.SendMessage(view.Handle(), win.WM_NOTIFY, 0, uintptr(unsafe.Pointer(&notice)))
	}
	if rowIndex != 0 || columnIndex != len(findingColumns)-1 {
		t.Fatalf("native click mapping failed: row=%d column=%d", rowIndex, columnIndex)
	}
}

func TestLongDetailPreviewPreservesUnicodeAndOriginal(t *testing.T) {
	text := strings.Repeat("原始完整证据", 20000) + "tail-original"
	preview := detailPreview(text)
	if !utf8.ValidString(preview) || len(preview) >= len(text) || !strings.Contains(preview, "256 KB") || !strings.HasSuffix(text, "tail-original") {
		t.Fatal("preview limit damaged text or original")
	}
	if detailPreview("短证据") != "短证据" {
		t.Fatal("short evidence changed")
	}
}

func Test7045ChineseDisplayAndExport(t *testing.T) {
	item := securitylog.Event{EventID: "7045", Category: "服务创建", ServiceName: "Google 更新程序服务（测试）", Details: "ServiceType=用户模式服务; StartType=自动启动", Command: `C:\测试目录\更新服务.exe`}
	rows := eventRows([]securitylog.Event{item})
	if len(rows) != 1 {
		t.Fatal("7045 row missing")
	}
	detail := eventDetailText(item)
	exported := strings.Join(eventExportRows(rows, []securitylog.Event{item})[0], "\n")
	for _, value := range []string{item.ServiceName, item.Details, item.Command} {
		if !strings.Contains(detail, value) || !strings.Contains(exported, value) {
			t.Fatalf("Chinese field lost in detail/export: %s", value)
		}
	}
}
