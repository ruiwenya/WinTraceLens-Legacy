//go:build windows

package securitylog

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestPreserveServiceEventUnicodeAndFullXML(t *testing.T) {
	xml := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager"/><EventID>7045</EventID><EventRecordID>123456</EventRecordID><TimeCreated SystemTime="2026-10-14T01:02:03Z"/><Channel>System</Channel><Computer>测试主机</Computer></System><EventData><Data Name="ServiceName">示例服务</Data><Data Name="ImagePath">cmd /c start &quot;&quot; C:\ProgramData\无害样例.bin</Data><Data Name="AccountName">LocalSystem</Data></EventData><RenderingInfo><Message>完整消息第二行</Message></RenderingInfo></Event>`
	words := utf16.Encode([]rune(xml))
	raw := make([]byte, 2+len(words)*2)
	raw[0], raw[1] = 0xff, 0xfe
	for i, value := range words {
		binary.LittleEndian.PutUint16(raw[2+i*2:], value)
	}
	rows, err := parsePreservedEvents(raw, "System")
	if err != nil || len(rows) != 1 {
		t.Fatalf("events=%+v err=%v", rows, err)
	}
	row := rows[0]
	if row.RecordID != "123456" || row.ServiceName != "示例服务" || row.Computer != "测试主机" || row.XML != xml || !strings.Contains(row.ImagePath, "无害样例.bin") || row.Message != "完整消息第二行" {
		t.Fatalf("record lost original fields: %+v", row)
	}
}

func TestPersistenceXPathAndOutputBounds(t *testing.T) {
	for _, value := range []string{"both'\"quotes", "bad\x00value", strings.Repeat("a", 513)} {
		if _, ok := eventXPathLiteral(value); ok {
			t.Fatalf("unsafe XPath allowed: %q", value)
		}
	}
	for _, value := range []string{"regular-service", "single'quote", "double\"quote"} {
		if _, ok := eventXPathLiteral(value); !ok {
			t.Fatalf("valid XPath rejected: %q", value)
		}
	}
	var out eventOutput
	if _, err := out.Write(make([]byte, 16*1024*1024+1)); err == nil || out.Len() != 0 {
		t.Fatal("event output limit not enforced")
	}
}
