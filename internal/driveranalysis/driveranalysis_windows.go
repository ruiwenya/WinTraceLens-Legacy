//go:build windows

package driveranalysis

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

const (
	serviceKernelDriver = 0x00000001
	serviceFileSystem   = 0x00000002
)

type registryDriver struct {
	Name         string
	DisplayName  string
	ImagePath    string
	Path         string
	RegistryPath string
	Type         uint64
	Start        uint64
}

type diskDriver struct {
	Name string
	Path string
	Info os.FileInfo
}

type driverEvent struct {
	Time        string
	EventID     string
	Source      string
	Name        string
	Path        string
	ServiceName string
	Details     string
}

type candidate struct {
	key      string
	kernel   *process.ModuleInfo
	services []registryDriver
	disk     *diskDriver
	events   []driverEvent
}

type driverWevtEvents struct {
	Events []driverWevtEvent `xml:"Event"`
}

type driverWevtEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID string `xml:"EventID"`
		Time    struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []driverWevtData `xml:"Data"`
	} `xml:"EventData"`
	UserData driverXMLNode `xml:"UserData"`
}

type driverWevtData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type driverXMLNode struct {
	XMLName  xml.Name
	Value    string          `xml:",chardata"`
	Children []driverXMLNode `xml:",any"`
}

var randomDriverNamePattern = regexp.MustCompile(`^[A-Za-z0-9]{10,32}$`)

func Collect(opts Options) (Snapshot, error) {
	opts = normalizeOptions(opts)
	snapshot := Snapshot{GeneratedAt: time.Now().Format("2006-01-02 15:04:05")}

	kernelModules, kernelErr := process.Modules(4, process.Options{HashLimitBytes: opts.HashLimitBytes})
	if kernelErr != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "内核模块: "+kernelErr.Error())
	}
	snapshot.SourceCounts.KernelModules = len(kernelModules)
	snapshot.Checks = append(snapshot.Checks, sourceCheck("PID 4 内核枚举", len(kernelModules), kernelErr))

	registryDrivers, registryErr := collectRegistryDrivers()
	if registryErr != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Services 驱动注册表: "+registryErr.Error())
	}
	snapshot.SourceCounts.RegistryDrivers = len(registryDrivers)
	snapshot.Checks = append(snapshot.Checks, sourceCheck("Services 驱动注册表", len(registryDrivers), registryErr))

	diskDrivers, diskErr := collectDiskDrivers()
	if diskErr != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "驱动目录: "+diskErr.Error())
	}
	snapshot.SourceCounts.DiskDrivers = len(diskDrivers)
	snapshot.Checks = append(snapshot.Checks, sourceCheck("System32\\drivers", len(diskDrivers), diskErr))

	events, eventErrors := collectDriverEvents(opts.MaxEvents)
	snapshot.CollectionErrors = append(snapshot.CollectionErrors, eventErrors...)
	snapshot.SourceCounts.LoadEvents = len(events)
	var eventErr error
	if len(eventErrors) > 0 {
		eventErr = fmt.Errorf("部分事件源不可用")
	}
	snapshot.Checks = append(snapshot.Checks, sourceCheck("7045 / 4697 / Sysmon 6", len(events), eventErr))

	candidates := correlateSources(kernelModules, registryDrivers, diskDrivers, events)
	metadata := make(map[string]struct {
		md5, hashError string
		signature      process.SignatureResult
	})
	for _, value := range candidates {
		if item, ok := analyzeCandidate(value, opts, metadata); ok {
			snapshot.Items = append(snapshot.Items, item)
		}
	}
	sort.SliceStable(snapshot.Items, func(i, j int) bool {
		if snapshot.Items[i].Score != snapshot.Items[j].Score {
			return snapshot.Items[i].Score > snapshot.Items[j].Score
		}
		return strings.ToLower(snapshot.Items[i].Name) < strings.ToLower(snapshot.Items[j].Name)
	})
	if len(snapshot.Items) > opts.MaxRecords {
		snapshot.Items = snapshot.Items[:opts.MaxRecords]
	}
	snapshot.CollectionErrors = uniqueStrings(snapshot.CollectionErrors)
	snapshot.SourceSummary = fmt.Sprintf("内核 %d / Services %d / 磁盘 %d / 加载事件 %d / 风险 %d",
		len(kernelModules), len(registryDrivers), len(diskDrivers), len(events), len(snapshot.Items))
	return snapshot, nil
}

func normalizeOptions(opts Options) Options {
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 500
	}
	if opts.MaxRecords > 2000 {
		opts.MaxRecords = 2000
	}
	if opts.MaxEvents <= 0 {
		opts.MaxEvents = 400
	}
	if opts.MaxEvents > 2000 {
		opts.MaxEvents = 2000
	}
	return opts
}

func sourceCheck(source string, count int, err error) SourceCheck {
	check := SourceCheck{Source: source, Status: "完成", Count: count}
	if err != nil {
		check.Status = "部分"
		check.Detail = err.Error()
	}
	return check
}

func collectRegistryDrivers() ([]registryDriver, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	drivers := make([]registryDriver, 0)
	for _, name := range names {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		typeValue, _, typeErr := key.GetIntegerValue("Type")
		if typeErr != nil || typeValue&(serviceKernelDriver|serviceFileSystem) == 0 {
			key.Close()
			continue
		}
		start, _, _ := key.GetIntegerValue("Start")
		imagePath, _, _ := key.GetStringValue("ImagePath")
		displayName, _, _ := key.GetStringValue("DisplayName")
		key.Close()
		drivers = append(drivers, registryDriver{
			Name:         name,
			DisplayName:  displayName,
			ImagePath:    imagePath,
			Path:         normalizeDriverPath(imagePath),
			RegistryPath: `HKLM\SYSTEM\CurrentControlSet\Services\` + name,
			Type:         typeValue,
			Start:        start,
		})
	}
	return drivers, nil
}

func collectDiskDrivers() ([]diskDriver, error) {
	root := filepath.Join(systemRoot(), "System32", "drivers")
	drivers := make([]diskDriver, 0)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if info == nil || info.IsDir() || !strings.EqualFold(filepath.Ext(info.Name()), ".sys") {
			return nil
		}
		drivers = append(drivers, diskDriver{Name: info.Name(), Path: filepath.Clean(path), Info: info})
		return nil
	})
	return drivers, err
}

func collectDriverEvents(maxEvents int) ([]driverEvent, []string) {
	type eventQuery struct {
		label string
		log   string
		id    int
	}
	queries := []eventQuery{
		{label: "系统日志 7045", log: "System", id: 7045},
		{label: "安全日志 4697", log: "Security", id: 4697},
		{label: "Sysmon 6", log: "Microsoft-Windows-Sysmon/Operational", id: 6},
	}
	events := make([]driverEvent, 0)
	errorsOut := make([]string, 0)
	for _, query := range queries {
		items, err := queryDriverEvents(query.log, query.id, maxEvents)
		if err != nil {
			errorsOut = append(errorsOut, query.label+": "+err.Error())
			continue
		}
		for _, event := range items {
			data := driverEventData(event)
			path := firstDriverValue(data, "ImageLoaded", "ServiceFileName", "ServiceFilePath", "ImagePath", "DriverName")
			name := filepath.Base(normalizeDriverPath(path))
			serviceName := firstDriverValue(data, "ServiceName", "Service", "Name")
			if serviceName == "" && (query.id == 7045 || query.id == 4697) {
				serviceName = firstDriverValue(data, "Param1")
			}
			if path == "" && (query.id == 7045 || query.id == 4697) {
				path = firstDriverValue(data, "Param2")
				name = filepath.Base(normalizeDriverPath(path))
			}
			events = append(events, driverEvent{
				Time:        formatDriverEventTime(event.System.Time.SystemTime),
				EventID:     event.System.EventID,
				Source:      query.label,
				Name:        name,
				Path:        normalizeDriverPath(path),
				ServiceName: serviceName,
				Details:     driverDataSummary(data),
			})
		}
	}
	return events, errorsOut
}

func queryDriverEvents(log string, eventID, maxEvents int) ([]driverWevtEvent, error) {
	query := fmt.Sprintf("*[System[(EventID=%d)]]", eventID)
	cmd := winexec.Command("wevtutil.exe", "qe", log, "/q:"+query, "/f:xml", "/rd:true", "/c:"+strconv.Itoa(maxEvents))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		message := strings.TrimSpace(decodeDriverOutput(stderr.Bytes()))
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("wevtutil 查询失败: %s", message)
	}
	text := strings.TrimSpace(decodeDriverOutput(out))
	if text == "" {
		return nil, nil
	}
	text = strings.ReplaceAll(text, `<?xml version="1.0" encoding="utf-16"?>`, "")
	text = strings.ReplaceAll(text, `<?xml version="1.0" encoding="utf-8"?>`, "")
	text = strings.ReplaceAll(text, `<?xml version="1.0"?>`, "")
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ToValidUTF8(text, "")
	text = "<Events>" + text + "</Events>"
	var container driverWevtEvents
	if err := xml.Unmarshal([]byte(text), &container); err != nil {
		return nil, fmt.Errorf("事件 XML 解析失败: %w", err)
	}
	return container.Events, nil
}

func driverEventData(event driverWevtEvent) map[string]string {
	data := make(map[string]string)
	for index, item := range event.EventData.Data {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = "Param" + strconv.Itoa(index+1)
		}
		data[name] = strings.TrimSpace(item.Value)
	}
	collectDriverXMLValues(event.UserData, data)
	return data
}

func collectDriverXMLValues(node driverXMLNode, data map[string]string) {
	for _, child := range node.Children {
		if value := strings.TrimSpace(child.Value); value != "" && child.XMLName.Local != "" {
			data[child.XMLName.Local] = value
		}
		collectDriverXMLValues(child, data)
	}
}

func correlateSources(kernel []process.ModuleInfo, services []registryDriver, disk []diskDriver, events []driverEvent) map[string]*candidate {
	out := make(map[string]*candidate)
	get := func(path, name string) *candidate {
		key := driverKey(path, name)
		if current, ok := out[key]; ok {
			return current
		}
		current := &candidate{key: key}
		out[key] = current
		return current
	}
	for index := range kernel {
		item := &kernel[index]
		get(item.Path, item.Name).kernel = item
	}
	for _, item := range services {
		name := filepath.Base(item.Path)
		if name == "." || name == "" {
			name = item.Name
		}
		get(item.Path, name).services = append(get(item.Path, name).services, item)
	}
	for index := range disk {
		item := &disk[index]
		get(item.Path, item.Name).disk = item
	}
	for _, item := range events {
		name := item.Name
		if name == "" {
			name = item.ServiceName
		}
		get(item.Path, name).events = append(get(item.Path, name).events, item)
	}
	return out
}

func analyzeCandidate(value *candidate, opts Options, metadata map[string]struct {
	md5, hashError string
	signature      process.SignatureResult
}) (Item, bool) {
	item := Item{Kind: "驱动"}
	if value.kernel != nil {
		if !strings.EqualFold(filepath.Ext(value.kernel.Name), ".sys") && !strings.EqualFold(value.kernel.Kind, "系统转储驱动") {
			return Item{}, false
		}
		item.Name = value.kernel.Name
		item.Kind = value.kernel.Kind
		item.Path = value.kernel.Path
		item.BaseAddress = value.kernel.BaseAddress
		item.SizeKB = value.kernel.SizeKB
		item.MD5 = value.kernel.MD5
		item.HashError = value.kernel.HashError
		item.Signature = value.kernel.Signature
		item.SignatureMsg = value.kernel.SignatureMsg
	}
	if len(value.services) > 0 {
		service := value.services[0]
		item.ServiceName = joinServiceNames(value.services)
		item.ServiceStart = serviceStartName(service.Start)
		item.ServiceType = serviceTypeName(service.Type)
		item.ServiceImage = service.ImagePath
		item.RegistryPath = service.RegistryPath
		if item.Name == "" {
			item.Name = filepath.Base(service.Path)
			if item.Name == "." || item.Name == "" {
				item.Name = service.Name
			}
		}
		if item.Path == "" {
			item.Path = service.Path
		}
	}
	if value.disk != nil {
		item.DiskPath = value.disk.Path
		if item.Path == "" {
			item.Path = value.disk.Path
		}
		if item.Name == "" {
			item.Name = value.disk.Name
		}
	}
	if item.Name == "" {
		item.Name = value.key
	}
	filePresent := value.disk != nil
	if !filePresent && item.Path != "" {
		if info, err := os.Stat(item.Path); err == nil && !info.IsDir() {
			filePresent = true
			item.DiskPath = item.Path
		}
	}
	serviceHasPath := false
	for _, service := range value.services {
		if strings.TrimSpace(service.Path) != "" {
			serviceHasPath = true
			break
		}
	}
	item.EventMatches = eventSummary(value.events)
	item.SourceDiff = fmt.Sprintf("内核=%s; Services=%s; 磁盘=%s; 事件=%d",
		present(value.kernel != nil), present(len(value.services) > 0), present(filePresent), len(value.events))

	reasons := make([]string, 0)
	evidence := make([]string, 0)
	score := 0
	knownDump := strings.EqualFold(item.Kind, "系统转储驱动")
	if value.kernel != nil && !filePresent && !knownDump {
		score += 55
		reasons = append(reasons, "内核已加载但文件系统未找到对应文件")
	}
	if len(value.services) > 0 && serviceHasPath && !filePresent && !knownDump {
		if value.services[0].Start <= 2 {
			score += 45
		} else {
			score += 25
		}
		reasons = append(reasons, "Services 驱动项指向的文件不存在")
	}
	if value.kernel != nil && len(value.services) == 0 && !knownDump {
		score += 18
		reasons = append(reasons, "内核枚举存在，但未关联到 Services 驱动项")
	}
	if suspiciousDriverPath(item.Path) {
		score += 35
		reasons = append(reasons, "驱动路径位于用户可写或临时目录")
	}
	if item.Path != "" && filePresent && item.Signature == "" && (value.kernel != nil || len(value.services) > 0 || suspiciousDriverName(item.Name)) {
		key := strings.ToLower(filepath.Clean(item.Path))
		cached, ok := metadata[key]
		if !ok {
			cached.md5, cached.hashError = process.HashFileMD5(item.Path, opts.HashLimitBytes)
			cached.signature = process.CheckSignature(item.Path)
			metadata[key] = cached
		}
		item.MD5, item.HashError = cached.md5, cached.hashError
		item.Signature, item.SignatureMsg = cached.signature.Status, cached.signature.Message
	}
	if suspiciousDriverName(item.Name) && !trustedDriverSignature(item.Signature) {
		score += 18
		reasons = append(reasons, "驱动名呈随机字符串特征，且未确认可信签名")
	}
	if strings.Contains(item.Signature, "签名异常") {
		score += 45
		reasons = append(reasons, "驱动签名校验异常")
	} else if strings.Contains(item.Signature, "无签名") {
		score += 30
		reasons = append(reasons, "驱动未发现可信签名")
	}
	if len(value.events) > 0 {
		evidence = append(evidence, item.EventMatches)
		if score >= 25 {
			score += 10
			reasons = append(reasons, "存在驱动安装或加载事件记录")
		}
	}
	if item.RegistryPath != "" {
		evidence = append(evidence, item.RegistryPath)
	}
	evidence = append(evidence, item.SourceDiff)
	if knownDump && score < 45 {
		return Item{}, false
	}
	if score < 30 {
		return Item{}, false
	}
	if score > 100 {
		score = 100
	}
	item.Score = score
	item.Level = riskLevel(score)
	item.Reason = strings.Join(uniqueStrings(reasons), "；")
	item.Evidence = strings.Join(uniqueStrings(evidence), "；")
	return item, true
}

func driverKey(path, name string) string {
	path = normalizeDriverPath(path)
	if path != "" {
		return "path:" + strings.ToLower(filepath.Clean(path))
	}
	return "name:" + strings.ToLower(strings.TrimSpace(name))
}

func normalizeDriverPath(raw string) string {
	value := strings.TrimSpace(strings.Trim(raw, `"`))
	if value == "" {
		return ""
	}
	if index := strings.Index(strings.ToLower(value), ".sys"); index >= 0 {
		value = value[:index+4]
	}
	root := systemRoot()
	drive := filepath.VolumeName(root)
	value = replaceFold(value, "%SystemRoot%", root)
	value = replaceFold(value, "%windir%", root)
	value = strings.ReplaceAll(value, "/", `\`)
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, `\??\`):
		value = value[len(`\??\`):]
	case strings.HasPrefix(lower, `\systemroot\`):
		value = filepath.Join(root, value[len(`\SystemRoot\`):])
	case strings.HasPrefix(lower, `systemroot\`):
		value = filepath.Join(root, value[len(`SystemRoot\`):])
	case strings.HasPrefix(lower, `system32\`):
		value = filepath.Join(root, value)
	case strings.HasPrefix(lower, `\windows\`) && drive != "":
		value = drive + value
	}
	if !filepath.IsAbs(value) && strings.HasSuffix(strings.ToLower(value), ".sys") {
		value = filepath.Join(root, value)
	}
	return filepath.Clean(value)
}

func systemRoot() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" {
		root = `C:\Windows`
	}
	return strings.TrimRight(root, `\/`)
}

func replaceFold(value, old, replacement string) string {
	lower, oldLower := strings.ToLower(value), strings.ToLower(old)
	index := strings.Index(lower, oldLower)
	if index < 0 {
		return value
	}
	return value[:index] + replacement + value[index+len(old):]
}

func suspiciousDriverPath(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	for _, marker := range []string{`\temp\`, `\appdata\`, `\programdata\`, `\users\`, `\public\`, `$recycle.bin`} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func suspiciousDriverName(name string) bool {
	base := strings.TrimSuffix(filepath.Base(strings.TrimSpace(name)), filepath.Ext(name))
	if !randomDriverNamePattern.MatchString(base) {
		return false
	}
	hasUpper, hasLower, hasDigit := false, false, false
	for _, char := range base {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		}
	}
	return hasDigit && hasUpper && hasLower
}

func trustedDriverSignature(signature string) bool {
	return signature == "系统文件" || signature == "已签名" || signature == "系统转储驱动"
}

func serviceStartName(value uint64) string {
	switch value {
	case 0:
		return "Boot"
	case 1:
		return "System"
	case 2:
		return "Auto"
	case 3:
		return "Demand"
	case 4:
		return "Disabled"
	default:
		return strconv.FormatUint(value, 10)
	}
}

func serviceTypeName(value uint64) string {
	parts := make([]string, 0, 2)
	if value&serviceKernelDriver != 0 {
		parts = append(parts, "Kernel")
	}
	if value&serviceFileSystem != 0 {
		parts = append(parts, "FileSystem")
	}
	return strings.Join(parts, "+")
}

func joinServiceNames(items []registryDriver) string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name)
	}
	return strings.Join(uniqueStrings(names), ", ")
}

func eventSummary(events []driverEvent) string {
	parts := make([]string, 0, len(events))
	for _, event := range events {
		value := strings.TrimSpace(event.Time + " " + event.Source)
		if event.ServiceName != "" {
			value += " 服务=" + event.ServiceName
		}
		parts = append(parts, value)
	}
	return strings.Join(uniqueStrings(parts), " | ")
}

func firstDriverValue(data map[string]string, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(data[name]); value != "" && value != "-" {
			return value
		}
	}
	return ""
}

func driverDataSummary(data map[string]string) string {
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

func formatDriverEventTime(raw string) string {
	value, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return value.Local().Format("2006-01-02 15:04:05")
}

func decodeDriverOutput(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0xff && raw[1] == 0xfe {
		return decodeDriverUTF16(raw[2:])
	}
	if looksDriverUTF16(raw) {
		return decodeDriverUTF16(raw)
	}
	return string(raw)
}

func looksDriverUTF16(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	checked, zeros := 0, 0
	for index := 1; index < len(raw) && checked < 200; index += 2 {
		checked++
		if raw[index] == 0 {
			zeros++
		}
	}
	return checked > 0 && zeros*100/checked > 60
}

func decodeDriverUTF16(raw []byte) string {
	values := make([]uint16, 0, len(raw)/2)
	for index := 0; index+1 < len(raw); index += 2 {
		values = append(values, uint16(raw[index])|uint16(raw[index+1])<<8)
	}
	return string(utf16.Decode(values))
}

func riskLevel(score int) string {
	switch {
	case score >= 75:
		return "高"
	case score >= 45:
		return "中"
	default:
		return "关注"
	}
}

func present(ok bool) string {
	if ok {
		return "有"
	}
	return "无"
}

func uniqueStrings(items []string) []string {
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
