//go:build windows

package securitylog

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

var xmlDeclaration = regexp.MustCompile(`<\?xml[^?]*\?>`)

// Query by service name before applying quotas. wevtutil is available on
// Windows 7/Server 2008 R2 and does not require PowerShell JSON cmdlets.
func CollectPersistenceMatches(names []string) ([]PreservedEvent, []string) {
	var events []PreservedEvent
	var warnings []string
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	seen := map[string]bool{}
	for i, name := range names {
		if i >= 16 {
			warnings = append(warnings, "关联服务事件达到 16 个服务上限，其余服务未查询。")
			break
		}
		literal, ok := eventXPathLiteral(name)
		if !ok {
			warnings = append(warnings, "服务名无法安全用于事件筛选，未查询该项。")
			continue
		}
		for _, channel := range []string{"System", "Security"} {
			if ctx.Err() != nil {
				return events, append(warnings, "关联服务事件补采达到 30 秒预算，不能确认未覆盖服务的安装时间。")
			}
			id := 7045
			if channel == "Security" {
				id = 4697
			}
			query := fmt.Sprintf("*[System[EventID=%d] and EventData[Data[@Name='ServiceName']=%s or Data[@Name='param1']=%s]]", id, literal, literal)
			cmd := winexec.WevtutilCommandContext(ctx, "qe", channel, "/q:"+query, "/f:xml", "/c:21", "/rd:true")
			var out eventOutput
			var stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &stderr
			if err := cmd.Run(); err != nil {
				message, decodeErr := winexec.DecodeEventOutput(stderr.Bytes())
				if decodeErr != nil {
					message = decodeErr.Error()
				}
				message = strings.TrimSpace(message)
				warnings = append(warnings, "关联服务事件 "+channel+": 查询失败或超时（"+err.Error()+"）；"+message)
				continue
			}
			rows, err := parsePreservedEvents(out.Bytes(), channel)
			if err != nil {
				warnings = append(warnings, "关联服务事件 "+channel+": XML 解析失败："+err.Error())
				continue
			}
			if len(rows) > 20 {
				warnings = append(warnings, channel+": 关联服务事件达到每服务每通道 20 条上限，保留最新记录。")
				rows = rows[:20]
			}
			for _, row := range rows {
				key := row.Channel + "|" + row.RecordID + "|" + row.TimeUTC
				if !seen[key] {
					seen[key] = true
					events = append(events, row)
				}
			}
		}
	}
	return events, warnings
}

type eventOutput struct{ bytes.Buffer }

func (b *eventOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 16*1024*1024 {
		return 0, fmt.Errorf("关联事件输出超过 16 MB 上限")
	}
	return b.Buffer.Write(p)
}

func eventXPathLiteral(value string) (string, bool) {
	if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return "", false
	}
	if !strings.Contains(value, "'") {
		return "'" + value + "'", true
	}
	if !strings.Contains(value, `"`) {
		return `"` + value + `"`, true
	}
	return "", false
}

func parsePreservedEvents(raw []byte, channel string) ([]PreservedEvent, error) {
	text, err := winexec.DecodeEventOutput(raw)
	if err != nil {
		return nil, err
	}
	text = strings.TrimPrefix(strings.TrimSpace(text), "\ufeff")
	text = "<Events>" + xmlDeclaration.ReplaceAllString(text, "") + "</Events>"
	decoder := xml.NewDecoder(strings.NewReader(text))
	var records []PreservedEvent
	for {
		offset := decoder.InputOffset()
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Event" {
			continue
		}
		var item struct {
			System struct {
				EventID  string `xml:"EventID"`
				RecordID string `xml:"EventRecordID"`
				Channel  string `xml:"Channel"`
				Computer string `xml:"Computer"`
				Provider struct {
					Name string `xml:"Name,attr"`
				} `xml:"Provider"`
				Time struct {
					Value string `xml:"SystemTime,attr"`
				} `xml:"TimeCreated"`
			} `xml:"System"`
			EventData struct {
				Data []wevtData `xml:"Data"`
			} `xml:"EventData"`
			RenderingInfo struct {
				Message string `xml:"Message"`
			} `xml:"RenderingInfo"`
		}
		if err := decoder.DecodeElement(&item, &start); err != nil {
			return nil, err
		}
		data := map[string]string{}
		for _, field := range item.EventData.Data {
			data[field.Name] = field.Value
		}
		record := PreservedEvent{Time: formatEventTime(item.System.Time.Value), TimeUTC: item.System.Time.Value,
			Source: channel, Channel: item.System.Channel, Provider: item.System.Provider.Name, Computer: item.System.Computer,
			EventID: item.System.EventID, RecordID: item.System.RecordID, ServiceName: firstValue(data, "ServiceName", "param1"),
			ImagePath: firstValue(data, "ImagePath", "ServiceFileName", "param2"), ServiceType: firstValue(data, "ServiceType", "param3"),
			StartType: firstValue(data, "StartType", "ServiceStartType", "param4"), Account: firstValue(data, "AccountName", "ServiceAccount", "param5"),
			SubjectSID: firstValue(data, "SubjectUserSid"), Message: item.RenderingInfo.Message,
			XML: strings.TrimSpace(text[offset:decoder.InputOffset()]), Details: "按服务名定向查询，独立于普通事件列表配额；原始 XML 已保全。"}
		if record.Channel == "" {
			record.Channel = channel
		}
		if record.Message == "" {
			record.Details += " 本机未返回格式化消息，详细字段以 XML 为准。"
		}
		records = append(records, record)
	}
	return records, nil
}
