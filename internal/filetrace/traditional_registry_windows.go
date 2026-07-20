//go:build windows

package filetrace

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func collectTraditionalRegistryArtifacts(maxRecords int) traditionalResult {
	result := traditionalResult{}
	appendResult := func(records []Record, warnings []string) {
		result.records = append(result.records, records...)
		result.warnings = append(result.warnings, warnings...)
	}
	appendResult(collectUserAssistAndPCA(maxRecords))
	appendResult(collectShimcacheArtifacts(maxRecords))
	appendResult(collectLiveAmcacheArtifacts(maxRecords))
	return result
}

func collectUserAssistAndPCA(maxRecords int) ([]Record, []string) {
	names, readErr := registry.USERS.ReadSubKeyNames(-1)
	if readErr != nil {
		return []Record{sourceStatus("UserAssist / PCA", "读取失败", `HKU`, readErr.Error())}, []string{"UserAssist / PCA: " + readErr.Error()}
	}

	limit := maxRecords / 5
	if limit < 50 {
		limit = 50
	}
	records := make([]Record, 0, limit+2)
	warnings := make([]string, 0)
	userAssistCount := 0
	pcaCount := 0
	loadedUsers := 0
	for _, sid := range names {
		if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-") || strings.HasSuffix(strings.ToLower(sid), "_classes") {
			continue
		}
		loadedUsers++
		uaRootPath := sid + `\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
		uaRoot, openErr := registry.OpenKey(registry.USERS, uaRootPath, registry.ENUMERATE_SUB_KEYS)
		if openErr == nil {
			guids, _ := uaRoot.ReadSubKeyNames(-1)
			_ = uaRoot.Close()
			for _, guid := range guids {
				countPath := uaRootPath + `\` + guid + `\Count`
				countKey, countErr := registry.OpenKey(registry.USERS, countPath, registry.QUERY_VALUE)
				if countErr != nil {
					continue
				}
				valueNames, _ := countKey.ReadValueNames(-1)
				for _, valueName := range valueNames {
					if userAssistCount >= limit {
						break
					}
					data, _, valueErr := countKey.GetBinaryValue(valueName)
					if valueErr != nil {
						continue
					}
					decoded := rot13(valueName)
					runCount := ""
					lastRun := ""
					if len(data) >= 8 {
						runCount = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(data[4:8])), 10)
					}
					if len(data) >= 68 {
						lastRun = fileTimeString(int64(binary.LittleEndian.Uint64(data[60:68])))
					}
					records = append(records, Record{
						Category:     "执行痕迹",
						Source:       "UserAssist",
						Name:         filepath.Base(strings.ReplaceAll(decoded, "/", `\`)),
						Path:         decoded,
						Directory:    windowsDirectory(decoded),
						Extension:    strings.ToLower(filepath.Ext(decoded)),
						LastRun:      lastRun,
						RunCount:     runCount,
						EvidenceTime: lastRun,
						TimeMeaning:  "UserAssist 记录的最近交互运行时间；主要反映 Explorer 图形界面启动",
						Details:      "SID=" + sid + "；注册表=HKU\\" + countPath + "；运行次数为注册表原始计数",
					})
					userAssistCount++
				}
				_ = countKey.Close()
			}
		}

		pcaPath := sid + `\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store`
		pcaKey, pcaErr := registry.OpenKey(registry.USERS, pcaPath, registry.QUERY_VALUE)
		if pcaErr == nil {
			valueNames, _ := pcaKey.ReadValueNames(-1)
			keyTime := registryKeyTime(pcaKey)
			for _, valueName := range valueNames {
				if pcaCount >= limit/2 {
					break
				}
				candidate := strings.TrimSpace(valueName)
				if candidate == "" {
					continue
				}
				records = append(records, Record{
					Category:     "执行痕迹",
					Source:       "PCA 执行记录",
					Name:         filepath.Base(strings.ReplaceAll(candidate, "/", `\`)),
					Path:         candidate,
					Directory:    windowsDirectory(candidate),
					Extension:    strings.ToLower(filepath.Ext(candidate)),
					Modified:     keyTime,
					EvidenceTime: keyTime,
					TimeMeaning:  "PCA Store 注册表键最后写入时间，不是单个值的可靠执行时间",
					Details:      "SID=" + sid + "；注册表=HKU\\" + pcaPath,
				})
				pcaCount++
			}
			_ = pcaKey.Close()
		}
	}
	status := fmt.Sprintf("已检查当前加载的用户 Hive %d 个；UserAssist=%d，PCA=%d。未登录用户的 NTUSER.DAT 不会被自动挂载。", loadedUsers, userAssistCount, pcaCount)
	records = append(records, sourceStatus("UserAssist / PCA", "采集完成", `HKU`, status))
	return records, warnings
}

func collectShimcacheArtifacts(maxRecords int) ([]Record, []string) {
	const path = `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
	key, err := openLocalMachineKey(path, registry.QUERY_VALUE)
	if err != nil {
		return []Record{sourceStatus("Shimcache", "不可用", `HKLM\`+path,
			"未找到 AppCompatCache。Win7/Server 2012 通常应存在；也可能被策略、清理工具或权限限制。")}, nil
	}
	data, _, valueErr := key.GetBinaryValue("AppCompatCache")
	keyTime := registryKeyTime(key)
	_ = key.Close()
	if valueErr != nil {
		return []Record{sourceStatus("Shimcache", "读取失败", `HKLM\`+path, valueErr.Error())}, []string{"Shimcache: " + valueErr.Error()}
	}
	limit := maxRecords / 5
	if limit < 50 {
		limit = 50
	}
	paths := extractUTF16Paths(data, limit)
	records := make([]Record, 0, len(paths)+1)
	for _, candidate := range paths {
		records = append(records, Record{
			Category:     "执行痕迹",
			Source:       "Shimcache 路径提取",
			Name:         filepath.Base(candidate),
			Path:         candidate,
			Directory:    windowsDirectory(candidate),
			Extension:    strings.ToLower(filepath.Ext(candidate)),
			Modified:     keyTime,
			EvidenceTime: "",
			TimeMeaning:  "当前仅从版本化二进制中提取路径；不提供条目级时间，也不能单独证明执行",
			Details:      "注册表=HKLM\\" + path + "；AppCompatCache字节数=" + strconv.Itoa(len(data)),
		})
	}
	status := fmt.Sprintf("已读取 AppCompatCache %d 字节，启发式提取路径 %d 条。Win7/Server 2012 的二进制结构不同，因此不猜测条目时间和执行标志。", len(data), len(paths))
	records = append(records, sourceStatus("Shimcache", "可用", `HKLM\`+path, status))
	return records, nil
}

func collectLiveAmcacheArtifacts(maxRecords int) ([]Record, []string) {
	root, err := openLocalMachineKey(`Amcache\Root`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		path := filepath.Join(systemRootPath(), `AppCompat\Programs\Amcache.hve`)
		return []Record{sourceStatus("Amcache", "系统未提供或未挂载", path,
			"Windows 7 只有安装兼容性遥测相关更新后才常见 Amcache；Server 2008 R2/2012 也可能没有。Legacy 在线模式不强制创建 VSS。")}, nil
	}
	_ = root.Close()
	programIDs := collectAmcacheProgramIDs()
	limit := maxRecords / 3
	if limit < 100 {
		limit = 100
	}
	records := make([]Record, 0, limit+1)
	schema := ""

	newRoot, newErr := openLocalMachineKey(`Amcache\Root\InventoryApplicationFile`, registry.ENUMERATE_SUB_KEYS)
	if newErr == nil {
		schema = "new"
		names, _ := newRoot.ReadSubKeyNames(-1)
		_ = newRoot.Close()
		for _, name := range names {
			if len(records) >= limit {
				break
			}
			keyPath := `Amcache\Root\InventoryApplicationFile\` + name
			key, openErr := openLocalMachineKey(keyPath, registry.QUERY_VALUE)
			if openErr != nil {
				continue
			}
			candidate := firstRegistryString(key, "LowerCaseLongPath", "LongPath", "FullPath")
			displayName := firstRegistryString(key, "Name", "OriginalFileName")
			if displayName == "" {
				displayName = filepath.Base(candidate)
			}
			programID := firstRegistryString(key, "ProgramId", "ProgramID")
			fileID := firstRegistryString(key, "FileId", "FileID")
			association := amcacheAssociation(programID, programIDs)
			stamp := registryKeyTime(key)
			size := registryInteger(key, "Size")
			publisher := firstRegistryString(key, "Publisher")
			binaryType := firstRegistryString(key, "BinaryType")
			product := firstRegistryString(key, "ProductName")
			linkDate := firstRegistryString(key, "LinkDate")
			_ = key.Close()
			if candidate == "" && displayName == "" && fileID == "" {
				continue
			}
			level, reason := amcacheSuspicion(candidate, displayName, association, binaryType)
			details := joinNonBlank("；",
				"键="+name,
				valueDetail("Publisher", publisher),
				valueDetail("Product", product),
				valueDetail("BinaryType", binaryType),
				valueDetail("LinkDate", linkDate),
				"Amcache 证明系统记录过该文件，不单独证明执行",
			)
			records = append(records, Record{
				Category:     "执行痕迹",
				Source:       "Amcache 在线注册表",
				Name:         displayName,
				Path:         candidate,
				Directory:    windowsDirectory(candidate),
				Extension:    strings.ToLower(filepath.Ext(displayName)),
				Size:         int64(size),
				Suspicion:    level,
				Reason:       reason,
				EvidenceTime: stamp,
				TimeMeaning:  "兼容性评估器记录或更新条目的时间，不代表文件执行时间",
				SHA1:         normalizeAmcacheSHA1(fileID),
				Schema:       "new",
				Association:  association,
				Details:      details,
			})
		}
	}

	oldRoot, oldErr := openLocalMachineKey(`Amcache\Root\File`, registry.ENUMERATE_SUB_KEYS)
	if oldErr == nil && len(records) < limit {
		if schema == "new" {
			schema = "new+old"
		} else {
			schema = "old"
		}
		volumes, _ := oldRoot.ReadSubKeyNames(-1)
		_ = oldRoot.Close()
		for _, volume := range volumes {
			volumePath := `Amcache\Root\File\` + volume
			volumeKey, openErr := openLocalMachineKey(volumePath, registry.ENUMERATE_SUB_KEYS)
			if openErr != nil {
				continue
			}
			fileKeys, _ := volumeKey.ReadSubKeyNames(-1)
			_ = volumeKey.Close()
			for _, name := range fileKeys {
				if len(records) >= limit {
					break
				}
				keyPath := volumePath + `\` + name
				key, openErr := openLocalMachineKey(keyPath, registry.QUERY_VALUE)
				if openErr != nil {
					continue
				}
				candidate := firstRegistryString(key, "LowerCaseLongPath", "FullPath", "15", "17")
				fileID := firstRegistryString(key, "101", "FileId", "FileID", "c")
				stamp := registryKeyTime(key)
				company := firstRegistryString(key, "1", "CompanyName", "Publisher")
				product := firstRegistryString(key, "0", "ProductName")
				_ = key.Close()
				if candidate == "" && fileID == "" {
					continue
				}
				records = append(records, Record{
					Category:     "执行痕迹",
					Source:       "Amcache 在线注册表",
					Name:         filepath.Base(candidate),
					Path:         candidate,
					Directory:    windowsDirectory(candidate),
					Extension:    strings.ToLower(filepath.Ext(candidate)),
					EvidenceTime: stamp,
					TimeMeaning:  "旧 schema 条目最后写入时间，可能与兼容性处理相关，但不能单独证明执行",
					SHA1:         normalizeAmcacheSHA1(fileID),
					Schema:       "old",
					Association:  "旧格式",
					Details:      joinNonBlank("；", valueDetail("Company", company), valueDetail("Product", product), "旧 schema 在线注册表条目"),
				})
			}
		}
	}
	if schema == "" {
		records = append(records, sourceStatus("Amcache", "结构不受支持", `HKLM\Amcache\Root`,
			"未找到 InventoryApplicationFile 或 File。旧系统补丁水平不同可能产生其他 schema。"))
		return records, nil
	}
	sort.SliceStable(records, func(i, j int) bool { return recordTimestamp(records[i]).After(recordTimestamp(records[j])) })
	records = append(records, sourceStatus("Amcache", "可用", `HKLM\Amcache\Root`,
		fmt.Sprintf("在线注册表 schema=%s，读取文件条目 %d。Legacy 模式不会把 Amcache 时间直接标记为执行时间。", schema, len(records))))
	return records, nil
}

func collectAmcacheProgramIDs() map[string]bool {
	known := make(map[string]bool)
	for _, path := range []string{`Amcache\Root\InventoryApplication`, `Amcache\Root\Programs`} {
		root, err := openLocalMachineKey(path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, _ := root.ReadSubKeyNames(-1)
		_ = root.Close()
		for _, name := range names {
			known[normalizeProgramID(name)] = true
			key, openErr := openLocalMachineKey(path+`\`+name, registry.QUERY_VALUE)
			if openErr == nil {
				for _, value := range []string{"ProgramId", "ProgramInstanceId"} {
					if text, _, valueErr := key.GetStringValue(value); valueErr == nil {
						known[normalizeProgramID(text)] = true
					}
				}
				_ = key.Close()
			}
		}
	}
	return known
}

func openLocalMachineKey(path string, access uint32) (registry.Key, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, access|registry.WOW64_64KEY)
	if err == nil {
		return key, nil
	}
	return registry.OpenKey(registry.LOCAL_MACHINE, path, access)
}

func registryKeyTime(key registry.Key) string {
	info, err := key.Stat()
	if err != nil {
		return ""
	}
	stamp := info.ModTime()
	if stamp.IsZero() || stamp.Year() < 1980 || stamp.Year() > 2200 {
		return ""
	}
	return stamp.Local().Format("2006-01-02 15:04:05")
}

func firstRegistryString(key registry.Key, names ...string) string {
	for _, name := range names {
		if value, _, err := key.GetStringValue(name); err == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
		}
		if values, _, err := key.GetStringsValue(name); err == nil && len(values) > 0 {
			return strings.TrimSpace(strings.Join(values, "; "))
		}
	}
	return ""
}

func registryInteger(key registry.Key, name string) uint64 {
	value, _, err := key.GetIntegerValue(name)
	if err != nil {
		return 0
	}
	return value
}

func rot13(value string) string {
	runes := []rune(value)
	for index, r := range runes {
		switch {
		case r >= 'a' && r <= 'z':
			runes[index] = 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			runes[index] = 'A' + (r-'A'+13)%26
		}
	}
	return string(runes)
}

func windowsDirectory(path string) string {
	path = strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(path), "/", `\`), `\`)
	if index := strings.LastIndex(path, `\`); index >= 0 {
		return path[:index]
	}
	return ""
}

func normalizeAmcacheSHA1(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	best := ""
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		run := value[start:end]
		if len(run) >= 40 {
			best = run[len(run)-40:]
		}
		start = -1
	}
	for index, r := range value {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			if start < 0 {
				start = index
			}
			continue
		}
		flush(index)
	}
	flush(len(value))
	return best
}

func normalizeProgramID(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func amcacheAssociation(programID string, known map[string]bool) string {
	id := normalizeProgramID(programID)
	if id == "" || strings.Trim(id, "0") == "" {
		return "未关联"
	}
	if known[id] {
		return "已关联"
	}
	if len(known) == 0 {
		return "应用清单不可用"
	}
	return "关联项缺失"
}

func amcacheSuspicion(path, name, association, binaryType string) (string, string) {
	if association != "未关联" && association != "关联项缺失" {
		return "", ""
	}
	reasons := []string{association}
	level := ""
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	switch {
	case strings.Contains(lower, `\temp\`):
		level = "高"
		reasons = append(reasons, "位于临时目录")
	case strings.Contains(lower, `\appdata\`), strings.Contains(lower, `\programdata\`):
		level = "中"
		reasons = append(reasons, "位于常见用户可写落地点")
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if looksRandomTraceName(base) {
		if level == "" {
			level = "中"
		}
		reasons = append(reasons, "文件名疑似随机")
	}
	if strings.HasPrefix(strings.ToLower(binaryType), "pe") {
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".scr" && ext != ".com" && path != "" {
			if level == "" {
				level = "中"
			}
			reasons = append(reasons, "PE 类型与扩展名不一致")
		}
	}
	if level == "" {
		return "", ""
	}
	return level, strings.Join(uniqueStrings(reasons), "；")
}

func valueDetail(name, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return name + "=" + strings.TrimSpace(value)
}

func joinNonBlank(separator string, values ...string) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return strings.Join(out, separator)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
