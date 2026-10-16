//go:build windows

package winexec

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os/exec"
	"unicode/utf16"
	"unicode/utf8"
)

// Keep the query's wire encoding explicit; the default uses a local code page.
func WevtutilCommand(args ...string) *exec.Cmd {
	return Command("wevtutil.exe", append(args, "/uni:true")...)
}

func WevtutilCommandContext(ctx context.Context, args ...string) *exec.Cmd {
	return CommandContext(ctx, "wevtutil.exe", append(args, "/uni:true")...)
}

// Unicode wevtutil output is UTF-16LE, including stderr without a BOM.
// Never replace/drop undecodable evidence bytes and continue as if intact.
func DecodeEventOutput(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		raw = raw[3:]
		if !utf8.Valid(raw) {
			return "", fmt.Errorf("事件输出包含无效 UTF-8 字节，未丢弃或替换证据")
		}
		return string(raw), nil
	}
	var order binary.ByteOrder = binary.LittleEndian
	if bytes.HasPrefix(raw, []byte{0xff, 0xfe}) {
		raw = raw[2:]
	} else if bytes.HasPrefix(raw, []byte{0xfe, 0xff}) {
		order, raw = binary.BigEndian, raw[2:]
	} else if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("<")) && !bytes.Contains(raw, []byte{0}) && utf8.Valid(raw) {
		// Accept already-normalized UTF-8 XML without guessing its contents.
		return string(raw), nil
	}
	if len(raw)%2 != 0 {
		return "", fmt.Errorf("事件 Unicode 输出长度异常，可能截断；未丢弃末尾字节")
	}
	words := make([]uint16, len(raw)/2)
	for i := range words {
		words[i] = order.Uint16(raw[i*2:])
	}
	for i := 0; i < len(words); i++ {
		value := words[i]
		if value >= 0xd800 && value <= 0xdbff {
			if i+1 >= len(words) || words[i+1] < 0xdc00 || words[i+1] > 0xdfff {
				return "", fmt.Errorf("事件 Unicode 输出包含不完整代理对，未替换原始字符")
			}
			i++
		} else if value >= 0xdc00 && value <= 0xdfff {
			return "", fmt.Errorf("事件 Unicode 输出包含孤立代理字符，未替换原始字符")
		}
	}
	return string(utf16.Decode(words)), nil
}
