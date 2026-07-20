//go:build windows

package filetrace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

type traditionalResult struct {
	records  []Record
	warnings []string
}

func collectTraditionalFileArtifacts(maxRecords int, since time.Time) traditionalResult {
	result := traditionalResult{}
	appendResult := func(records []Record, warnings []string) {
		result.records = append(result.records, records...)
		result.warnings = append(result.warnings, warnings...)
	}
	appendResult(collectPrefetchArtifacts(maxRecords, since))
	appendResult(collectRecentAndJumpListArtifacts(maxRecords, since))
	appendResult(collectSRUMArtifact())
	appendResult(collectPowerShellHistoryArtifacts(maxRecords))
	return result
}

func sourceStatus(source, status, path, detail string) Record {
	return Record{
		Category:    "取证源状态",
		Source:      source,
		Name:        status,
		Path:        path,
		TimeMeaning: "状态记录，不是文件活动时间",
		Details:     detail,
	}
}

func collectPrefetchArtifacts(maxRecords int, since time.Time) ([]Record, []string) {
	root := filepath.Join(systemRootPath(), "Prefetch")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []Record{sourceStatus("Prefetch", "目录不存在或未启用", root,
				"Windows 7 客户端通常启用 Prefetch；Windows Server 2008 R2/2012 常见默认关闭或目录为空。缺失不代表没有程序执行。")}, nil
		}
		return []Record{sourceStatus("Prefetch", "读取失败", root, "请确认以管理员权限运行。")}, []string{"Prefetch: " + err.Error()}
	}

	type item struct {
		path string
		info os.FileInfo
	}
	items := make([]item, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".pf") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		if !since.IsZero() && info.ModTime().Before(since) {
			continue
		}
		items = append(items, item{path: filepath.Join(root, entry.Name()), info: info})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].info.ModTime().After(items[j].info.ModTime()) })
	limit := maxRecords / 5
	if limit < 50 {
		limit = 50
	}
	if limit > maxRecords {
		limit = maxRecords
	}
	if len(items) > limit {
		items = items[:limit]
	}

	records := make([]Record, 0, len(items)+1)
	parsed := 0
	for _, entry := range items {
		meta, parseErr := parsePrefetchFile(entry.path)
		name := strings.TrimSuffix(entry.info.Name(), filepath.Ext(entry.info.Name()))
		if index := strings.LastIndex(name, "-"); index > 0 && len(name)-index == 9 {
			name = name[:index]
		}
		lastRun := ""
		runCount := ""
		timeMeaning := "Prefetch 文件最后写入时间，仅作为近期活动近似值"
		details := fmt.Sprintf("PF版本=未知；PF文件=%s", entry.info.Name())
		if parseErr == nil {
			parsed++
			if meta.Executable != "" {
				name = meta.Executable
			}
			lastRun = meta.LastRun
			if meta.RunCount > 0 {
				runCount = strconv.FormatUint(uint64(meta.RunCount), 10)
			}
			timeMeaning = "Prefetch 内部最近运行时间；可证明系统记录过该映像，但仍需结合其他证据"
			details = fmt.Sprintf("PF版本=%d；PF文件=%s", meta.Version, entry.info.Name())
			if len(meta.RunTimes) > 1 {
				details += "；历史运行时间=" + strings.Join(meta.RunTimes, ", ")
			}
		} else {
			details += "；内部结构未解析: " + parseErr.Error()
		}
		modified := entry.info.ModTime().Format("2006-01-02 15:04:05")
		evidenceTime := lastRun
		if evidenceTime == "" {
			evidenceTime = modified
		}
		records = append(records, Record{
			Category:     "执行痕迹",
			Source:       "Prefetch",
			Name:         name,
			Path:         entry.path,
			Directory:    root,
			Extension:    ".pf",
			Size:         entry.info.Size(),
			Modified:     modified,
			LastRun:      lastRun,
			RunCount:     runCount,
			EvidenceTime: evidenceTime,
			TimeMeaning:  timeMeaning,
			Details:      details,
		})
	}
	status := fmt.Sprintf("目录中 PF=%d，当前时间范围=%d，成功解析内部结构=%d。", countPrefetchEntries(entries), len(items), parsed)
	if len(items) == 0 {
		status += "当前范围没有记录；可扩大时间范围。Server 版本也可能默认关闭 Prefetch。"
	}
	records = append(records, sourceStatus("Prefetch", "可用", root, status))
	return records, nil
}

type prefetchMetadata struct {
	Version    uint32
	Executable string
	RunCount   uint32
	LastRun    string
	RunTimes   []string
}

func parsePrefetchFile(path string) (prefetchMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return prefetchMetadata{}, err
	}
	if len(data) < 0x9c {
		return prefetchMetadata{}, fmt.Errorf("文件过小")
	}
	if bytes.Equal(data[:3], []byte{'M', 'A', 'M'}) {
		return prefetchMetadata{}, fmt.Errorf("压缩 Prefetch 格式不在 Legacy 解析范围，保留文件元数据")
	}
	version := binary.LittleEndian.Uint32(data[0:4])
	if string(data[4:8]) != "SCCA" {
		return prefetchMetadata{}, fmt.Errorf("缺少 SCCA 签名")
	}
	meta := prefetchMetadata{Version: version}
	if len(data) >= 136 {
		meta.Executable = strings.TrimSpace(decodeUTF16LE(data[16:136]))
	}
	var runOffset int
	var timeOffsets []int
	switch version {
	case 17:
		runOffset = 0x90
		timeOffsets = []int{0x78}
	case 23:
		runOffset = 0x98
		timeOffsets = []int{0x80}
	case 26:
		runOffset = 0xD0
		for offset := 0x80; offset <= 0xB8; offset += 8 {
			timeOffsets = append(timeOffsets, offset)
		}
	default:
		return prefetchMetadata{}, fmt.Errorf("未支持的 PF 版本 %d", version)
	}
	if runOffset+4 <= len(data) {
		meta.RunCount = binary.LittleEndian.Uint32(data[runOffset : runOffset+4])
	}
	for _, offset := range timeOffsets {
		if offset+8 > len(data) {
			continue
		}
		stamp := fileTimeString(int64(binary.LittleEndian.Uint64(data[offset : offset+8])))
		if stamp != "" {
			meta.RunTimes = append(meta.RunTimes, stamp)
		}
	}
	if len(meta.RunTimes) > 0 {
		meta.LastRun = meta.RunTimes[0]
	}
	return meta, nil
}

func countPrefetchEntries(entries []os.DirEntry) int {
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".pf") {
			count++
		}
	}
	return count
}

func collectRecentAndJumpListArtifacts(maxRecords int, since time.Time) ([]Record, []string) {
	profiles, warnings := userProfileDirectories()
	records := make([]Record, 0, maxRecords/3)
	perSource := maxRecords / 8
	if perSource < 30 {
		perSource = 30
	}
	lnkCount := 0
	jumpCount := 0
	for _, profile := range profiles {
		recentRoot := filepath.Join(profile, `AppData\Roaming\Microsoft\Windows\Recent`)
		entries, err := os.ReadDir(recentRoot)
		if err == nil {
			type lnkItem struct {
				path string
				info os.FileInfo
			}
			items := make([]lnkItem, 0, len(entries))
			for _, entry := range entries {
				if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".lnk") {
					continue
				}
				info, infoErr := entry.Info()
				if infoErr != nil || (!since.IsZero() && info.ModTime().Before(since)) {
					continue
				}
				items = append(items, lnkItem{path: filepath.Join(recentRoot, entry.Name()), info: info})
			}
			sort.SliceStable(items, func(i, j int) bool { return items[i].info.ModTime().After(items[j].info.ModTime()) })
			if len(items) > perSource {
				items = items[:perSource]
			}
			for _, item := range items {
				meta, parseErr := parseShellLink(item.path)
				target := meta.Target
				if target == "" {
					target = item.path
				}
				detail := "LNK文件=" + item.path
				if meta.Arguments != "" {
					detail += "；参数=" + meta.Arguments
				}
				if meta.WorkingDirectory != "" {
					detail += "；工作目录=" + meta.WorkingDirectory
				}
				if meta.TargetModified != "" {
					detail += "；LNK保存的目标修改时间=" + meta.TargetModified
				}
				if parseErr != nil {
					detail += "；目标解析不完整=" + parseErr.Error()
				}
				stamp := item.info.ModTime().Format("2006-01-02 15:04:05")
				records = append(records, Record{
					Category:     "快捷方式痕迹",
					Source:       "Recent LNK",
					Name:         item.info.Name(),
					Path:         target,
					Directory:    filepath.Dir(target),
					Extension:    strings.ToLower(filepath.Ext(target)),
					Size:         item.info.Size(),
					Modified:     stamp,
					EvidenceTime: stamp,
					TimeMeaning:  "Recent 快捷方式文件最后写入时间，不等于目标文件执行时间",
					Details:      detail,
				})
				lnkCount++
			}
		}

		for _, leaf := range []string{
			`AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`,
			`AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`,
		} {
			root := filepath.Join(profile, leaf)
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				info, infoErr := entry.Info()
				if infoErr != nil || (!since.IsZero() && info.ModTime().Before(since)) {
					continue
				}
				path := filepath.Join(root, entry.Name())
				stamp := info.ModTime().Format("2006-01-02 15:04:05")
				details := "JumpList 容器；当前 Legacy 模式不把容器更新时间当作程序执行时间"
				if targets := extractUTF16PathsFromFile(path, 8); len(targets) > 0 {
					details += "；可识别路径=" + strings.Join(targets, " | ")
				}
				records = append(records, Record{
					Category:     "快捷方式痕迹",
					Source:       "JumpList",
					Name:         entry.Name(),
					Path:         path,
					Directory:    root,
					Extension:    strings.ToLower(filepath.Ext(entry.Name())),
					Size:         info.Size(),
					Modified:     stamp,
					EvidenceTime: stamp,
					TimeMeaning:  "JumpList 容器最后写入时间；目标级执行时间尚未解析",
					Details:      details,
				})
				jumpCount++
				if jumpCount >= perSource*2 {
					break
				}
			}
		}
	}
	recentStatus := fmt.Sprintf("已检查 %d 个用户配置目录；当前时间范围读取 Recent LNK %d 条。", len(profiles), lnkCount)
	if lnkCount == 0 {
		recentStatus += "可能没有近期快捷方式、目录已清理，或相应用户 Hive/配置目录不可访问。"
	}
	records = append(records, sourceStatus("Recent LNK", "采集完成", filepath.Join(systemDrivePath(), "Users"), recentStatus))
	jumpStatus := fmt.Sprintf("JumpList 自 Windows 7 起可用；当前时间范围定位容器 %d 个。目标级明细需专用 OLE/JumpList 解析器复核。", jumpCount)
	records = append(records, sourceStatus("JumpList", "证据定位", filepath.Join(systemDrivePath(), "Users"), jumpStatus))
	return records, warnings
}

type shellLinkMetadata struct {
	Target           string
	Arguments        string
	WorkingDirectory string
	TargetModified   string
}

func parseShellLink(path string) (shellLinkMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return shellLinkMetadata{}, err
	}
	if len(data) < 0x4c || binary.LittleEndian.Uint32(data[:4]) != 0x4c {
		return shellLinkMetadata{}, fmt.Errorf("不是标准 Shell Link")
	}
	flags := binary.LittleEndian.Uint32(data[20:24])
	meta := shellLinkMetadata{TargetModified: fileTimeString(int64(binary.LittleEndian.Uint64(data[44:52])))}
	offset := 0x4c
	if flags&0x1 != 0 {
		if offset+2 > len(data) {
			return meta, fmt.Errorf("IDList 长度缺失")
		}
		offset += 2 + int(binary.LittleEndian.Uint16(data[offset:offset+2]))
	}
	if flags&0x2 != 0 && offset+4 <= len(data) {
		size := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if size >= 0x1c && offset+size <= len(data) {
			linkInfo := data[offset : offset+size]
			headerSize := int(binary.LittleEndian.Uint32(linkInfo[4:8]))
			localOffset := int(binary.LittleEndian.Uint32(linkInfo[16:20]))
			suffixOffset := int(binary.LittleEndian.Uint32(linkInfo[24:28]))
			local := readCString(linkInfo, localOffset)
			suffix := readCString(linkInfo, suffixOffset)
			if headerSize >= 0x24 && len(linkInfo) >= 36 {
				unicodeLocal := int(binary.LittleEndian.Uint32(linkInfo[28:32]))
				unicodeSuffix := int(binary.LittleEndian.Uint32(linkInfo[32:36]))
				if value := readUTF16CString(linkInfo, unicodeLocal); value != "" {
					local = value
				}
				if value := readUTF16CString(linkInfo, unicodeSuffix); value != "" {
					suffix = value
				}
			}
			meta.Target = joinLinkTarget(local, suffix)
			offset += size
		}
	}
	unicodeStrings := flags&0x80 != 0
	readStringData := func() string {
		if offset+2 > len(data) {
			return ""
		}
		count := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		byteCount := count
		if unicodeStrings {
			byteCount *= 2
		}
		if byteCount < 0 || offset+byteCount > len(data) {
			offset = len(data)
			return ""
		}
		value := string(data[offset : offset+byteCount])
		if unicodeStrings {
			value = decodeUTF16LE(data[offset : offset+byteCount])
		}
		offset += byteCount
		return strings.TrimSpace(strings.TrimRight(value, "\x00"))
	}
	if flags&0x4 != 0 {
		_ = readStringData()
	}
	if flags&0x8 != 0 {
		relative := readStringData()
		if meta.Target == "" && looksLikeWindowsPath(relative) {
			meta.Target = relative
		}
	}
	if flags&0x10 != 0 {
		meta.WorkingDirectory = readStringData()
	}
	if flags&0x20 != 0 {
		meta.Arguments = readStringData()
	}
	if meta.Target == "" {
		return meta, fmt.Errorf("未解析到目标路径")
	}
	return meta, nil
}

func joinLinkTarget(base, suffix string) string {
	base = strings.TrimSpace(base)
	suffix = strings.TrimSpace(suffix)
	if base == "" {
		return suffix
	}
	if suffix == "" || strings.EqualFold(filepath.Base(base), suffix) {
		return base
	}
	if strings.HasSuffix(strings.ToLower(base), strings.ToLower(`\`+suffix)) {
		return base
	}
	return filepath.Join(base, suffix)
}

func readCString(data []byte, offset int) string {
	if offset <= 0 || offset >= len(data) {
		return ""
	}
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}
	return strings.TrimSpace(string(data[offset:end]))
}

func readUTF16CString(data []byte, offset int) string {
	if offset <= 0 || offset+1 >= len(data) {
		return ""
	}
	end := offset
	for end+1 < len(data) && (data[end] != 0 || data[end+1] != 0) {
		end += 2
	}
	return strings.TrimSpace(decodeUTF16LE(data[offset:end]))
}

func decodeUTF16LE(data []byte) string {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		value := binary.LittleEndian.Uint16(data[i : i+2])
		if value == 0 {
			break
		}
		units = append(units, value)
	}
	return string(utf16.Decode(units))
}

func extractUTF16PathsFromFile(path string, limit int) []string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}
	return extractUTF16Paths(data, limit)
}

func extractUTF16Paths(data []byte, limit int) []string {
	if limit <= 0 {
		limit = 20
	}
	seen := make(map[string]bool)
	paths := make([]string, 0, limit)
	for offset := 0; offset+6 < len(data) && len(paths) < limit; offset++ {
		if !isASCIILetter(data[offset]) || data[offset+1] != 0 || data[offset+2] != ':' || data[offset+3] != 0 || data[offset+4] != '\\' || data[offset+5] != 0 {
			continue
		}
		end := offset
		for end+1 < len(data) && end-offset < 2048 {
			value := binary.LittleEndian.Uint16(data[end : end+2])
			if value == 0 || value < 0x20 || value == '<' || value == '>' || value == '|' || value == '"' {
				break
			}
			end += 2
		}
		candidate := strings.TrimSpace(decodeUTF16LE(data[offset:end]))
		if !looksLikeWindowsPath(candidate) {
			continue
		}
		key := strings.ToLower(candidate)
		if !seen[key] {
			seen[key] = true
			paths = append(paths, candidate)
		}
		offset = end
	}
	return paths
}

func collectSRUMArtifact() ([]Record, []string) {
	path := filepath.Join(systemRootPath(), `System32\sru\SRUDB.dat`)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Record{sourceStatus("SRUM", "系统未提供或未启用", path,
				"Windows 7/Server 2008 R2 不提供 SRUM；Windows 8/Server 2012 及以后才可能存在，且服务或策略可能关闭记录。")}, nil
		}
		return []Record{sourceStatus("SRUM", "读取失败", path, err.Error())}, []string{"SRUM: " + err.Error()}
	}
	stamp := info.ModTime().Format("2006-01-02 15:04:05")
	return []Record{{
		Category:     "网络与应用痕迹",
		Source:       "SRUM 证据定位",
		Name:         "SRUDB.dat",
		Path:         path,
		Directory:    filepath.Dir(path),
		Extension:    ".dat",
		Size:         info.Size(),
		Modified:     stamp,
		EvidenceTime: stamp,
		TimeMeaning:  "SRUM 数据库文件最后写入时间，不代表某个程序的具体活动时间",
		Details:      "已定位 SRUM ESE 数据库；Legacy 在线模式不直接解析 ESE 明细，建议导出副本后使用专用 SRUM/ESE 解析器。",
	}}, nil
}

func collectPowerShellHistoryArtifacts(maxRecords int) ([]Record, []string) {
	profiles, warnings := userProfileDirectories()
	limit := maxRecords / 10
	if limit < 30 {
		limit = 30
	}
	records := make([]Record, 0, limit+1)
	files := 0
	commands := 0
	for _, profile := range profiles {
		for _, leaf := range []string{
			`AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`,
			`AppData\Roaming\Microsoft\PowerShell\PSReadLine`,
		} {
			root := filepath.Join(profile, leaf)
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), "_history.txt") {
					continue
				}
				path := filepath.Join(root, entry.Name())
				info, infoErr := entry.Info()
				if infoErr != nil {
					continue
				}
				data, readErr := os.ReadFile(path)
				if readErr != nil {
					warnings = append(warnings, "PowerShell PSReadLine: "+readErr.Error())
					continue
				}
				files++
				lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
				start := 0
				if len(lines) > limit {
					start = len(lines) - limit
				}
				stamp := info.ModTime().Format("2006-01-02 15:04:05")
				for index := start; index < len(lines) && commands < limit; index++ {
					command := strings.TrimSpace(strings.TrimPrefix(lines[index], "\ufeff"))
					if command == "" {
						continue
					}
					display := command
					if len(display) > 240 {
						display = display[:240] + "..."
					}
					records = append(records, Record{
						Category:     "命令历史",
						Source:       "PowerShell PSReadLine",
						Name:         display,
						Path:         path,
						Directory:    root,
						Extension:    ".txt",
						Modified:     stamp,
						EvidenceTime: stamp,
						TimeMeaning:  "历史文件最后写入时间；单条命令没有可靠执行时间",
						Details:      fmt.Sprintf("历史文件相对行号=%d", index+1),
					})
					commands++
				}
			}
		}
	}
	detail := fmt.Sprintf("历史文件=%d，读取命令=%d。Windows PowerShell 2 默认不包含 PSReadLine，因此 Win7/Server 2008 R2 未发现历史文件通常是正常情况。", files, commands)
	records = append(records, sourceStatus("PowerShell PSReadLine", "采集完成", filepath.Join(systemDrivePath(), "Users"), detail))
	return records, warnings
}

func userProfileDirectories() ([]string, []string) {
	root := filepath.Join(systemDrivePath(), "Users")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, []string{"用户配置目录: " + err.Error()}
	}
	profiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if name == "all users" || name == "default user" || name == "default" {
			continue
		}
		profiles = append(profiles, filepath.Join(root, entry.Name()))
	}
	return profiles, nil
}

func systemDrivePath() string {
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))
	if drive == "" {
		drive = `C:`
	}
	drive = strings.TrimRight(drive, `\`)
	if len(drive) == 2 && drive[1] == ':' {
		return drive + `\`
	}
	return drive
}

func systemRootPath() string {
	root := strings.TrimSpace(os.Getenv("SystemRoot"))
	if root == "" {
		root = strings.TrimSpace(os.Getenv("windir"))
	}
	if root == "" {
		root = filepath.Join(systemDrivePath(), "Windows")
	}
	return root
}

func looksLikeWindowsPath(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) >= 4 && isASCIILetter(value[0]) && value[1] == ':' && (value[2] == '\\' || value[2] == '/')
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
