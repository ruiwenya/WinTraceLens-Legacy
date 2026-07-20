//go:build windows

package history

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

type historyWevtEvents struct {
	Events []historyWevtEvent `xml:"Event"`
}

type historyWevtEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID string `xml:"EventID"`
		Time    struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []historyWevtData `xml:"Data"`
	} `xml:"EventData"`
	UserData historyXMLNode `xml:"UserData"`
}

type historyWevtData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type historyXMLNode struct {
	XMLName  xml.Name
	Value    string           `xml:",chardata"`
	Children []historyXMLNode `xml:",any"`
}

func collectNativeHistory(opts Options, maxRecords int) (Snapshot, error) {
	snapshot := Snapshot{GeneratedAt: time.Now().Format("2006-01-02 15:04:05")}

	eventRecords, eventErrors := collectHistoryEvents(opts, maxRecords)
	snapshot.Records = append(snapshot.Records, eventRecords...)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, eventErrors...)

	staticSnapshot, staticErr := collectTextFallback(opts, maxRecords, "")
	if staticErr != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "基础通信快照: "+staticErr.Error())
	} else {
		snapshot.Records = append(snapshot.Records, staticSnapshot.Records...)
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, staticSnapshot.CollectionErrors...)
	}

	firewallRecords, firewallErrors := collectFirewallLog(opts, maxRecords)
	snapshot.Records = append(snapshot.Records, firewallRecords...)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, firewallErrors...)

	snapshot.Records = limitHistoryRecords(deduplicateHistoryRecords(snapshot.Records), maxRecords)
	snapshot.CollectionErrors = uniqueHistoryStrings(localizeHistoryErrors(snapshot.CollectionErrors))
	return snapshot, nil
}

func collectHistoryEvents(opts Options, maxRecords int) ([]Record, []string) {
	type sourceQuery struct {
		name string
		log  string
		ids  []int
	}
	queries := []sourceQuery{
		{name: "Sysmon", log: "Microsoft-Windows-Sysmon/Operational", ids: []int{3, 22}},
		{name: "DNS Client 日志", log: "Microsoft-Windows-DNS-Client/Operational"},
		{name: "安全日志 WFP", log: "Security", ids: []int{5156, 5157}},
	}
	records := make([]Record, 0)
	errorsOut := make([]string, 0)
	perSource := maxRecords
	if perSource > 1500 {
		perSource = 1500
	}
	for _, query := range queries {
		events, err := queryHistoryEvents(query.log, query.ids, opts, perSource)
		if err != nil {
			errorsOut = append(errorsOut, query.name+": "+err.Error())
			continue
		}
		for _, event := range events {
			if record, ok := historyRecordFromEvent(query.name, event); ok {
				records = append(records, record)
			}
		}
	}
	return records, errorsOut
}

func queryHistoryEvents(logName string, ids []int, opts Options, maxRecords int) ([]historyWevtEvent, error) {
	xpath := buildHistoryXPath(ids, opts)
	args := []string{"qe", logName, "/q:" + xpath, "/f:xml", "/rd:true", "/c:" + strconv.Itoa(maxRecords)}
	cmd := winexec.Command("wevtutil.exe", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		message := strings.TrimSpace(decodeCommandOutput(stderr.Bytes()))
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("wevtutil 查询失败: %s", message)
	}
	data := bytes.TrimSpace(out)
	if len(data) == 0 {
		return nil, nil
	}
	text := strings.TrimSpace(decodeCommandOutput(data))
	text = strings.ReplaceAll(text, `<?xml version="1.0" encoding="utf-16"?>`, "")
	text = strings.ReplaceAll(text, `<?xml version="1.0" encoding="utf-8"?>`, "")
	text = strings.ReplaceAll(text, `<?xml version="1.0"?>`, "")
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ToValidUTF8(text, "")
	text = "<Events>" + text + "</Events>"
	var container historyWevtEvents
	if err := xml.Unmarshal([]byte(text), &container); err != nil {
		return nil, fmt.Errorf("事件 XML 解析失败: %w", err)
	}
	return container.Events, nil
}

func buildHistoryXPath(ids []int, opts Options) string {
	conditions := make([]string, 0, 3)
	if len(ids) > 0 {
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			parts = append(parts, "EventID="+strconv.Itoa(id))
		}
		conditions = append(conditions, "("+strings.Join(parts, " or ")+")")
	}
	if !opts.StartTime.IsZero() {
		conditions = append(conditions, "TimeCreated[@SystemTime>='"+opts.StartTime.UTC().Format(time.RFC3339Nano)+"']")
	}
	if !opts.EndTime.IsZero() {
		conditions = append(conditions, "TimeCreated[@SystemTime<='"+opts.EndTime.UTC().Format(time.RFC3339Nano)+"']")
	}
	if len(conditions) == 0 {
		return "*"
	}
	return "*[System[" + strings.Join(conditions, " and ") + "]]"
}

func historyRecordFromEvent(source string, event historyWevtEvent) (Record, bool) {
	data := historyEventData(event)
	record := Record{
		Time:    formatHistoryEventTime(event.System.Time.SystemTime),
		Source:  source,
		EventID: strings.TrimSpace(event.System.EventID),
		User:    firstHistoryValue(data, "User", "SubjectUserName", "UserName"),
		Details: historyDataSummary(data),
	}
	if record.User == "" {
		record.User = strings.TrimSpace(event.System.Security.UserID)
	}

	switch source {
	case "Sysmon":
		switch record.EventID {
		case "3":
			record.Source = "Sysmon 网络连接"
			record.Process = firstHistoryValue(data, "Image", "ProcessName")
			record.PID = firstHistoryValue(data, "ProcessId", "ProcessID")
			record.Proto = normalizeHistoryProtocol(firstHistoryValue(data, "Protocol"))
			record.Local = joinHistoryEndpoint(firstHistoryValue(data, "SourceIp"), firstHistoryValue(data, "SourcePort"))
			record.Remote = joinHistoryEndpoint(firstHistoryValue(data, "DestinationIp"), firstHistoryValue(data, "DestinationPort"))
			record.Query = firstHistoryValue(data, "DestinationHostname")
			record.Action = firstHistoryValue(data, "Initiated")
		case "22":
			record.Source = "Sysmon DNS"
			record.Process = firstHistoryValue(data, "Image", "ProcessName")
			record.PID = firstHistoryValue(data, "ProcessId", "ProcessID")
			record.Query = firstHistoryValue(data, "QueryName")
			result := firstHistoryValue(data, "QueryResults")
			if result != "" {
				record.Details = "解析结果=" + result + "; " + record.Details
			}
		default:
			return Record{}, false
		}
	case "DNS Client 日志":
		record.Process = firstHistoryValue(data, "Image", "ProcessName", "Application", "AppName")
		record.PID = firstHistoryValue(data, "ClientProcessId", "ProcessId", "ProcessID", "PID")
		record.Query = firstHistoryValue(data, "QueryName", "QName", "Name", "HostName", "Hostname", "Query")
		if record.Query == "" {
			record.Query = event.System.Provider.Name
		}
		result := firstHistoryValue(data, "QueryResults", "Results", "Response", "Answers", "Address", "IpAddress")
		if result != "" {
			record.Details = "解析结果=" + result + "; " + record.Details
		}
	case "安全日志 WFP":
		record.Process = firstHistoryValue(data, "Application", "ProcessName")
		record.PID = firstHistoryValue(data, "ProcessID", "ProcessId")
		record.Proto = normalizeHistoryProtocol(firstHistoryValue(data, "Protocol"))
		record.Local = joinHistoryEndpoint(firstHistoryValue(data, "SourceAddress"), firstHistoryValue(data, "SourcePort"))
		record.Remote = joinHistoryEndpoint(firstHistoryValue(data, "DestAddress", "DestinationAddress"), firstHistoryValue(data, "DestPort", "DestinationPort"))
		if record.EventID == "5156" {
			record.Action = "允许"
		} else {
			record.Action = "阻止"
		}
	}
	return record, true
}

func historyEventData(event historyWevtEvent) map[string]string {
	data := make(map[string]string)
	for index, item := range event.EventData.Data {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = "Param" + strconv.Itoa(index+1)
		}
		data[name] = strings.TrimSpace(item.Value)
	}
	collectHistoryXMLValues(event.UserData, data)
	return data
}

func collectHistoryXMLValues(node historyXMLNode, data map[string]string) {
	for _, child := range node.Children {
		value := strings.TrimSpace(child.Value)
		if value != "" && child.XMLName.Local != "" {
			data[child.XMLName.Local] = value
		}
		collectHistoryXMLValues(child, data)
	}
}

func firstHistoryValue(data map[string]string, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(data[name]); value != "" && value != "-" {
			return value
		}
	}
	return ""
}

func historyDataSummary(data map[string]string) string {
	keys := make([]string, 0, len(data))
	for key, value := range data {
		if strings.TrimSpace(value) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+data[key])
	}
	return strings.Join(parts, "; ")
}

func formatHistoryEventTime(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return raw
	}
	return value.Local().Format("2006-01-02 15:04:05")
}

func normalizeHistoryProtocol(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "6", "tcp":
		return "TCP"
	case "17", "udp":
		return "UDP"
	default:
		return strings.TrimSpace(value)
	}
}

func joinHistoryEndpoint(address, port string) string {
	address = strings.TrimSpace(address)
	port = strings.TrimSpace(port)
	if address == "" || address == "-" {
		return ""
	}
	if port == "" || port == "-" || port == "0" {
		return address
	}
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		return "[" + address + "]:" + port
	}
	return address + ":" + port
}

func collectFirewallLog(opts Options, maxRecords int) ([]Record, []string) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "LogFiles", "Firewall", "pfirewall.log")
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, []string{"防火墙日志: 未找到 pfirewall.log，可能未启用 Windows 防火墙日志。"}
		}
		return nil, []string{"防火墙日志: 无法读取 " + path + ": " + err.Error()}
	}
	defer file.Close()

	fields := make([]string, 0)
	records := make([]Record, 0, maxRecords)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#Fields:") {
			fields = strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#Fields:")))
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || len(fields) == 0 {
			continue
		}
		values := strings.Fields(line)
		row := make(map[string]string, len(fields))
		for i, field := range fields {
			if i < len(values) {
				row[field] = values[i]
			}
		}
		timestamp := strings.TrimSpace(row["date"] + " " + row["time"])
		if !historyTimeInRange(timestamp, opts) {
			continue
		}
		record := Record{
			Time:    timestamp,
			Source:  "防火墙日志",
			Process: cleanHistoryDash(row["path"]),
			Proto:   normalizeHistoryProtocol(row["protocol"]),
			Local:   joinHistoryEndpoint(row["src-ip"], row["src-port"]),
			Remote:  joinHistoryEndpoint(row["dst-ip"], row["dst-port"]),
			Action:  cleanHistoryDash(row["action"]),
			Details: cleanHistoryDash(row["info"]),
		}
		records = append(records, record)
		if len(records) > maxRecords {
			copy(records, records[len(records)-maxRecords:])
			records = records[:maxRecords]
		}
	}
	if err := scanner.Err(); err != nil {
		return records, []string{"防火墙日志: 读取过程中断: " + err.Error()}
	}
	return records, nil
}

func historyTimeInRange(raw string, opts Options) bool {
	value, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(raw), time.Local)
	if err != nil {
		return true
	}
	if !opts.StartTime.IsZero() && value.Before(opts.StartTime) {
		return false
	}
	if !opts.EndTime.IsZero() && value.After(opts.EndTime) {
		return false
	}
	return true
}

func cleanHistoryDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "-" {
		return ""
	}
	return value
}

func deduplicateHistoryRecords(records []Record) []Record {
	seen := make(map[string]struct{}, len(records))
	out := make([]Record, 0, len(records))
	for _, record := range records {
		key := strings.Join([]string{record.Time, record.Source, record.EventID, record.PID, record.Local, record.Remote, record.Query, record.Action}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, record)
	}
	return out
}

func limitHistoryRecords(records []Record, maxRecords int) []Record {
	timed := make([]Record, 0, len(records))
	static := make([]Record, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.Time) == "" {
			static = append(static, record)
		} else {
			timed = append(timed, record)
		}
	}
	sort.SliceStable(timed, func(i, j int) bool { return timed[i].Time > timed[j].Time })
	if len(records) <= maxRecords {
		return append(timed, static...)
	}
	reserve := maxRecords / 4
	if reserve < 20 {
		reserve = 20
	}
	if reserve > len(static) {
		reserve = len(static)
	}
	if reserve > maxRecords {
		reserve = maxRecords
	}
	timedLimit := maxRecords - reserve
	if timedLimit > len(timed) {
		timedLimit = len(timed)
	}
	out := append([]Record(nil), timed[:timedLimit]...)
	out = append(out, static[:reserve]...)
	return out
}

func uniqueHistoryStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
