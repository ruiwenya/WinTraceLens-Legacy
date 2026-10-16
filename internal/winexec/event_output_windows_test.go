//go:build windows

package winexec

import (
	"context"
	"encoding/binary"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf16"
)

func eventTestUTF16(text string, order binary.ByteOrder, bom []byte) []byte {
	words := utf16.Encode([]rune(text))
	raw := make([]byte, len(bom)+len(words)*2)
	copy(raw, bom)
	for i, value := range words {
		order.PutUint16(raw[len(bom)+i*2:], value)
	}
	return raw
}

func TestEventOutputUnicodeRoundTrip(t *testing.T) {
	for _, original := range []string{
		`<Event><Data Name="ServiceName">Google 更新程序服务（测试）</Data><Data Name="ServiceType">用户模式服务</Data><Data Name="StartType">按需启动</Data></Event>`,
		"无法打开日志查询。\r\n拒绝访问。\r\n",
		"汉字",
		"中文服务 \U0001f50d",
	} {
		for _, raw := range [][]byte{
			eventTestUTF16(original, binary.LittleEndian, []byte{0xff, 0xfe}),
			eventTestUTF16(original, binary.LittleEndian, nil),
			eventTestUTF16(original, binary.BigEndian, []byte{0xfe, 0xff}),
			append([]byte{0xef, 0xbb, 0xbf}, []byte(original)...),
		} {
			actual, err := DecodeEventOutput(raw)
			if err != nil || actual != original {
				t.Fatalf("Unicode output corrupted: actual=%q expected=%q error=%v", actual, original, err)
			}
		}
	}
	if text, err := DecodeEventOutput([]byte("<Event>UTF-8 中文</Event>")); err != nil || text != "<Event>UTF-8 中文</Event>" {
		t.Fatal("normalized XML corrupted")
	}
}

func TestCorruptEventOutputIsNotSilentlyDropped(t *testing.T) {
	for _, raw := range [][]byte{
		{0xff, 0xfe, 0x41},
		{0xff, 0xfe, 0x00, 0xd8},
		{0xff, 0xfe, 0x00, 0xdc},
		{0xef, 0xbb, 0xbf, 0xff},
	} {
		if text, err := DecodeEventOutput(raw); err == nil || text != "" {
			t.Fatalf("corrupt evidence accepted: %x -> %q / %v", raw, text, err)
		}
	}
}

func TestEventCommandsForceUnicodeAndHideConsole(t *testing.T) {
	for _, cmd := range []*exec.Cmd{
		WevtutilCommand("qe", "System"),
		WevtutilCommandContext(context.Background(), "qe", "Security"),
	} {
		if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow || !strings.Contains(strings.Join(cmd.Args, " "), "/uni:true") {
			t.Fatal("event query lacks Unicode or hidden console")
		}
	}
}
