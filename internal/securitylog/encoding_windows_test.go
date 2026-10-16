//go:build windows

package securitylog

import (
	"encoding/binary"
	"encoding/xml"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

func Test7045ServiceFieldsRemainChinese(t *testing.T) {
	const rawXML = `<Event><System><Provider Name="Service Control Manager"/><EventID>7045</EventID><EventRecordID>88</EventRecordID><Channel>System</Channel><TimeCreated SystemTime="2026-10-15T01:00:00Z"/></System><EventData><Data Name="ServiceName">Google 更新程序服务（测试）</Data><Data Name="ImagePath">C:\测试目录\更新服务.exe</Data><Data Name="ServiceType">用户模式服务</Data><Data Name="StartType">按需启动</Data><Data Name="AccountName">LocalSystem</Data></EventData></Event>`
	words := utf16.Encode([]rune(rawXML))
	raw := make([]byte, 2+len(words)*2)
	raw[0], raw[1] = 0xff, 0xfe
	for i, value := range words {
		binary.LittleEndian.PutUint16(raw[2+i*2:], value)
	}
	decoded, err := winexec.DecodeEventOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	var item wevtEvent
	if err := xml.Unmarshal([]byte(decoded), &item); err != nil {
		t.Fatal(err)
	}
	view := eventFromWevt(item, wevtQuery{source: "System", category: "服务创建"})
	if view.ServiceName != "Google 更新程序服务（测试）" || view.Command != `C:\测试目录\更新服务.exe` || !strings.Contains(view.Details, "ServiceType=用户模式服务") || !strings.Contains(view.Details, "StartType=按需启动") {
		t.Fatalf("service view corrupted: %+v", view)
	}
	preserved, err := parsePreservedEvents(raw, "System")
	if err != nil || len(preserved) != 1 {
		t.Fatalf("preserved event failed: %v", err)
	}
	if preserved[0].ServiceName != view.ServiceName || preserved[0].ServiceType != "用户模式服务" || preserved[0].StartType != "按需启动" || preserved[0].XML != rawXML {
		t.Fatalf("linked event corrupted: %+v", preserved[0])
	}
}

func TestLive7045UnicodeRead(t *testing.T) {
	if os.Getenv("WTL_EVENT_ENCODING_SMOKE") != "1" {
		t.Skip("explicit read-only local event smoke test")
	}
	rows, err := queryWevtutil(wevtQuery{logName: "System", source: "System", category: "服务创建", ids: []int{7045}, limit: 3}, Options{})
	if err != nil || len(rows) == 0 {
		t.Fatalf("7045 query failed: %v", err)
	}
	for _, raw := range rows {
		item := eventFromWevt(raw, wevtQuery{source: "System", category: "服务创建"})
		if strings.ContainsAny(item.ServiceName+item.Details+item.Command, "\ufffd\x00") {
			t.Fatalf("invalid event text: %+v", item)
		}
		t.Logf("7045 service=%s details=%s", item.ServiceName, item.Details)
	}
	service := eventFromWevt(rows[0], wevtQuery{source: "System", category: "服务创建"}).ServiceName
	matched, warnings := CollectPersistenceMatches([]string{service})
	found := false
	for _, item := range matched {
		if item.EventID == "7045" && item.ServiceName == service && item.RecordID != "" && strings.Contains(item.XML, service) {
			found = true
		}
	}
	if !found {
		t.Fatalf("linked service Unicode event not retained; warnings=%v", warnings)
	}
}
