//go:build windows

package process

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

const (
	th32csSnapProcess              = 0x00000002
	th32csSnapModule               = 0x00000008
	th32csSnapModule32             = 0x00000010
	processQueryInformation        = 0x0400
	processQueryLimitedInformation = 0x1000
	processVMRead                  = 0x0010
	maxPath                        = 260
	maxModuleName32                = 255
)

var (
	modKernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot  = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW            = modKernel32.NewProc("Process32NextW")
	procModule32FirstW            = modKernel32.NewProc("Module32FirstW")
	procModule32NextW             = modKernel32.NewProc("Module32NextW")
	procCloseHandle               = modKernel32.NewProc("CloseHandle")
	procOpenProcess               = modKernel32.NewProc("OpenProcess")
	procQueryFullProcessImageName = modKernel32.NewProc("QueryFullProcessImageNameW")
	procGetProcessTimes           = modKernel32.NewProc("GetProcessTimes")
	procGetProcessHandleCount     = modKernel32.NewProc("GetProcessHandleCount")
	modPsapi                      = syscall.NewLazyDLL("psapi.dll")
	procGetProcessMemoryInfo      = modPsapi.NewProc("GetProcessMemoryInfo")
)

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [maxPath]uint16
}

type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	Module       uintptr
	ModuleName   [maxModuleName32 + 1]uint16
	ExePath      [maxPath]uint16
}

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

type processCPUSample struct {
	Kernel uint64
	User   uint64
}

func Collect(opts Options) ([]Info, error) {
	entries, err := snapshotProcesses()
	if err != nil {
		return nil, err
	}

	names := make(map[uint32]string, len(entries))
	for _, entry := range entries {
		names[entry.ProcessID] = utf16String(entry.ExeFile[:])
	}

	hashCache := make(map[string]struct {
		value string
		err   string
	})

	signatureCache := make(map[string]SignatureResult)
	connectionCount := make(map[uint32]int)
	if connections, err := CollectConnections(); err == nil {
		for _, connection := range connections {
			connectionCount[connection.PID]++
		}
	}
	commandLines := queryProcessCommandLines()
	cpuStart := sampleProcessCPU(entries)
	sampleStartedAt := time.Now()
	time.Sleep(350 * time.Millisecond)
	cpuEnd := sampleProcessCPU(entries)
	cpuElapsed := time.Since(sampleStartedAt)

	items := make([]Info, 0, len(entries))
	for _, entry := range entries {
		path, pathErr := queryProcessPath(entry.ProcessID)
		if entry.ProcessID == 4 && path == "" {
			pathErr = "System 是内核进程，没有可按普通文件访问的可执行路径，进程 MD5 不适用；请在模块列表查看内核驱动。"
		} else if entry.ProcessID == 0 && path == "" {
			pathErr = "System Idle Process 没有可执行文件路径，MD5 不适用。"
		}
		createdAt := queryProcessCreatedAt(entry.ProcessID)
		fileCreated, fileModified := fileTimes(path)
		workingSetKB := queryProcessWorkingSetKB(entry.ProcessID)
		handleCount := queryProcessHandleCount(entry.ProcessID)
		cpuPercent := formatCPUPercent(calculateCPUPercent(entry.ProcessID, cpuStart, cpuEnd, cpuElapsed))

		var md5Value, hashErr string
		var sig SignatureResult
		if path != "" {
			key := strings.ToLower(path)
			if !opts.SkipHashes {
				if cached, ok := hashCache[key]; ok {
					md5Value = cached.value
					hashErr = cached.err
				} else {
					md5Value, hashErr = fileMD5(path, opts.HashLimitBytes)
					hashCache[key] = struct {
						value string
						err   string
					}{value: md5Value, err: hashErr}
				}
			}

			if opts.SkipSignatures {
				sig = SignatureResult{}
			} else if cached, ok := signatureCache[key]; ok {
				sig = cached
			} else {
				sig = CheckSignature(path)
				signatureCache[key] = sig
			}
		}

		items = append(items, Info{
			PID:             entry.ProcessID,
			Name:            names[entry.ProcessID],
			ParentPID:       entry.ParentProcessID,
			ParentName:      names[entry.ParentProcessID],
			CreatedAt:       formatTime(createdAt),
			CommandLine:     commandLines[entry.ProcessID],
			Path:            path,
			FileCreated:     formatTime(fileCreated),
			FileModified:    formatTime(fileModified),
			MD5:             md5Value,
			Signature:       sig.Status,
			SignatureMsg:    sig.Message,
			ConnectionCount: connectionCount[entry.ProcessID],
			CPUPercent:      cpuPercent,
			WorkingSetKB:    workingSetKB,
			ThreadCount:     entry.Threads,
			HandleCount:     handleCount,
			HashError:       hashErr,
			PathError:       pathErr,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].PID < items[j].PID
	})

	return items, nil
}

func queryProcessCommandLines() map[uint32]string {
	cmd := winexec.Command("wmic.exe", "process", "get", "ProcessId,CommandLine", "/format:csv")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	reader := csv.NewReader(bytes.NewReader([]byte(decodeCommandOutput(out))))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return nil
	}

	header := records[0]
	index := make(map[string]int, len(header))
	for i, name := range header {
		index[strings.TrimSpace(name)] = i
	}
	pidIndex, hasPID := index["ProcessId"]
	commandIndex, hasCommand := index["CommandLine"]
	if !hasPID || !hasCommand {
		return nil
	}

	outMap := make(map[uint32]string, len(records)-1)
	for _, record := range records[1:] {
		if pidIndex < 0 || pidIndex >= len(record) || commandIndex < 0 || commandIndex >= len(record) {
			continue
		}
		pidValue := strings.TrimSpace(record[pidIndex])
		if pidValue == "" {
			continue
		}
		var pid uint64
		if _, err := fmt.Sscanf(pidValue, "%d", &pid); err != nil || pid == 0 {
			continue
		}
		outMap[uint32(pid)] = strings.TrimSpace(record[commandIndex])
	}
	return outMap
}

func decodeCommandOutput(raw []byte) string {
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			return decodeUTF16LE(raw[2:])
		}
		if raw[0] == 0xfe && raw[1] == 0xff {
			u16 := make([]uint16, 0, (len(raw)-2)/2)
			for i := 2; i+1 < len(raw); i += 2 {
				u16 = append(u16, uint16(raw[i])<<8|uint16(raw[i+1]))
			}
			return string(utf16.Decode(u16))
		}
	}
	if looksUTF16LE(raw) {
		return decodeUTF16LE(raw)
	}
	return string(raw)
}

func looksUTF16LE(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	checked := 0
	zeros := 0
	for i := 1; i < len(raw) && checked < 200; i += 2 {
		checked++
		if raw[i] == 0 {
			zeros++
		}
	}
	return checked > 0 && zeros*100/checked > 60
}

func decodeUTF16LE(raw []byte) string {
	u16 := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	return string(utf16.Decode(u16))
}

func Modules(pid uint32, opts Options) ([]ModuleInfo, error) {
	if pid == 4 {
		return kernelModules(opts)
	}
	return processModules(pid, opts)
}

func processModules(pid uint32, opts Options) ([]ModuleInfo, error) {
	handle, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapModule|th32csSnapModule32, uintptr(pid))
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, err
	}
	defer procCloseHandle.Call(handle)

	var entry moduleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, err := procModule32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, err
	}

	hashCache := make(map[string]struct {
		value string
		err   string
	})
	signatureCache := make(map[string]SignatureResult)

	var modules []ModuleInfo
	for {
		path := utf16String(entry.ExePath[:])
		key := strings.ToLower(path)

		var md5Value, hashErr string
		if path != "" && !opts.SkipHashes {
			if cached, ok := hashCache[key]; ok {
				md5Value = cached.value
				hashErr = cached.err
			} else {
				md5Value, hashErr = fileMD5(path, opts.HashLimitBytes)
				hashCache[key] = struct {
					value string
					err   string
				}{value: md5Value, err: hashErr}
			}
		}

		var sig SignatureResult
		if path != "" && !opts.SkipSignatures {
			if cached, ok := signatureCache[key]; ok {
				sig = cached
			} else {
				sig = CheckSignature(path)
				signatureCache[key] = sig
			}
		}

		modules = append(modules, ModuleInfo{
			Name:         utf16String(entry.ModuleName[:]),
			Kind:         "进程模块",
			Path:         path,
			BaseAddress:  fmt.Sprintf("0x%X", entry.ModBaseAddr),
			SizeKB:       entry.ModBaseSize / 1024,
			MD5:          md5Value,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})

		ret, _, _ = procModule32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	sort.Slice(modules, func(i, j int) bool {
		return strings.ToLower(modules[i].Name) < strings.ToLower(modules[j].Name)
	})

	return modules, nil
}

func snapshotProcesses() ([]processEntry32, error) {
	handle, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, err
	}
	defer procCloseHandle.Call(handle)

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procProcess32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, err
	}

	var entries []processEntry32
	for {
		entries = append(entries, entry)
		ret, _, _ = procProcess32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return entries, nil
}

func sampleProcessCPU(entries []processEntry32) map[uint32]processCPUSample {
	out := make(map[uint32]processCPUSample, len(entries))
	for _, entry := range entries {
		if sample, ok := queryProcessCPUSample(entry.ProcessID); ok {
			out[entry.ProcessID] = sample
		}
	}
	return out
}

func queryProcessCPUSample(pid uint32) (processCPUSample, bool) {
	handle, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 {
		return processCPUSample{}, false
	}
	defer procCloseHandle.Call(handle)

	var creation, exit, kernel, user syscall.Filetime
	ret, _, _ := procGetProcessTimes.Call(
		handle,
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		return processCPUSample{}, false
	}
	return processCPUSample{
		Kernel: filetimeTicks(kernel),
		User:   filetimeTicks(user),
	}, true
}

func calculateCPUPercent(pid uint32, start, end map[uint32]processCPUSample, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	first, ok := start[pid]
	if !ok {
		return 0
	}
	last, ok := end[pid]
	if !ok {
		return 0
	}
	firstTotal := first.Kernel + first.User
	lastTotal := last.Kernel + last.User
	if lastTotal <= firstTotal {
		return 0
	}
	elapsedTicks := float64(elapsed.Nanoseconds()) / 100
	if elapsedTicks <= 0 {
		return 0
	}
	cores := runtime.NumCPU()
	if cores < 1 {
		cores = 1
	}
	return float64(lastTotal-firstTotal) * 100 / elapsedTicks / float64(cores)
}

func filetimeTicks(value syscall.Filetime) uint64 {
	return uint64(value.HighDateTime)<<32 | uint64(value.LowDateTime)
}

func formatCPUPercent(value float64) string {
	if value < 0.05 {
		return "0.0"
	}
	if value > 100 {
		value = 100
	}
	return fmt.Sprintf("%.1f", value)
}

func queryProcessWorkingSetKB(pid uint32) uint64 {
	handle, _, _ := procOpenProcess.Call(processQueryInformation|processVMRead, 0, uintptr(pid))
	if handle == 0 {
		handle, _, _ = procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	}
	if handle == 0 {
		return 0
	}
	defer procCloseHandle.Call(handle)

	var counters processMemoryCounters
	counters.CB = uint32(unsafe.Sizeof(counters))
	ret, _, _ := procGetProcessMemoryInfo.Call(
		handle,
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.CB),
	)
	if ret == 0 {
		return 0
	}
	return uint64(counters.WorkingSetSize) / 1024
}

func queryProcessHandleCount(pid uint32) uint32 {
	handle, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 {
		return 0
	}
	defer procCloseHandle.Call(handle)

	var count uint32
	ret, _, _ := procGetProcessHandleCount.Call(handle, uintptr(unsafe.Pointer(&count)))
	if ret == 0 {
		return 0
	}
	return count
}

func queryProcessPath(pid uint32) (string, string) {
	handle, _, err := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 {
		return "", err.Error()
	}
	defer procCloseHandle.Call(handle)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	ret, _, err := procQueryFullProcessImageName.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", err.Error()
	}

	return syscall.UTF16ToString(buf[:size]), ""
}

func queryProcessCreatedAt(pid uint32) time.Time {
	handle, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 {
		return time.Time{}
	}
	defer procCloseHandle.Call(handle)

	var creation, exit, kernel, user syscall.Filetime
	ret, _, _ := procGetProcessTimes.Call(
		handle,
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		return time.Time{}
	}

	return time.Unix(0, creation.Nanoseconds()).Local()
}

func fileTimes(path string) (time.Time, time.Time) {
	if path == "" {
		return time.Time{}, time.Time{}
	}

	var data syscall.Win32FileAttributeData
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return time.Time{}, time.Time{}
	}
	if err := syscall.GetFileAttributesEx(p, syscall.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&data))); err != nil {
		if stat, statErr := os.Stat(path); statErr == nil {
			return time.Time{}, stat.ModTime().Local()
		}
		return time.Time{}, time.Time{}
	}

	created := time.Unix(0, data.CreationTime.Nanoseconds()).Local()
	modified := time.Unix(0, data.LastWriteTime.Nanoseconds()).Local()
	return created, modified
}

func utf16String(value []uint16) string {
	return syscall.UTF16ToString(value)
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format("2006-01-02 15:04:05")
}
