//go:build windows

package host

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

type psSnapshot struct {
	Services        []psService     `json:"Services"`
	ScheduledTasks  []psTask        `json:"ScheduledTasks"`
	Users           []UserInfo      `json:"Users"`
	StartupRegistry []psStartupItem `json:"StartupRegistry"`
	StartupFolders  []psStartupItem `json:"StartupFolders"`
	ImageHijacks    []psImageHijack `json:"ImageHijacks"`
	Persistence     []psPersistence `json:"Persistence"`
}

type psService struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	State       string `json:"State"`
	StartMode   string `json:"StartMode"`
	Account     string `json:"StartName"`
	Command     string `json:"PathName"`
}

type psStartupItem struct {
	Source   string `json:"Source"`
	Name     string `json:"Name"`
	Command  string `json:"Command"`
	Location string `json:"Location"`
}

type psTask struct {
	Name    string `json:"Name"`
	Path    string `json:"Path"`
	State   string `json:"State"`
	Status  string `json:"Status"`
	Author  string `json:"Author"`
	Command string `json:"Command"`
}

type psImageHijack struct {
	Image        string `json:"Image"`
	Debugger     string `json:"Debugger"`
	RegistryPath string `json:"RegistryPath"`
}

type psPersistence struct {
	Category string `json:"Category"`
	Name     string `json:"Name"`
	Value    string `json:"Value"`
	Location string `json:"Location"`
}

type taskXML struct {
	RegistrationInfo struct {
		Author string `xml:"Author"`
	} `xml:"RegistrationInfo"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func Collect(opts Options) (Snapshot, error) {
	var snapshot Snapshot

	psData, err := collectPowerShellSnapshot()
	if err == nil {
		snapshot.Services = servicesFromPS(psData.Services, opts)
		snapshot.ScheduledTasks = tasksFromPS(psData.ScheduledTasks, opts)
		snapshot.Users = psData.Users
		snapshot.StartupItems = append(snapshot.StartupItems, startupFromPS(psData.StartupRegistry, opts)...)
		snapshot.StartupItems = append(snapshot.StartupItems, startupFromPS(psData.StartupFolders, opts)...)
		snapshot.ImageHijacks = hijacksFromPS(psData.ImageHijacks, opts)
		snapshot.PersistenceItems = persistenceFromPS(psData.Persistence, opts)
	}

	if len(snapshot.Services) == 0 {
		services, err := collectServicesLegacy(opts)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Services: "+err.Error())
		} else {
			snapshot.Services = services
		}
	}

	if len(snapshot.ScheduledTasks) == 0 {
		tasks, err := collectScheduledTasks(opts)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Scheduled tasks: "+err.Error())
		} else {
			snapshot.ScheduledTasks = tasks
		}
	}

	if len(snapshot.Users) == 0 {
		users, err := collectUsersLegacy()
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Users: "+err.Error())
		} else {
			snapshot.Users = users
		}
	}

	if len(snapshot.StartupItems) == 0 {
		startup, err := collectStartupFallback(opts)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Startup: "+err.Error())
		} else {
			snapshot.StartupItems = startup
		}
	}

	if len(snapshot.ImageHijacks) == 0 {
		hijacks, err := collectImageHijacksReg(opts)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "IFEO: "+err.Error())
		} else {
			snapshot.ImageHijacks = hijacks
		}
	}

	if len(snapshot.PersistenceItems) == 0 {
		persistence, err := collectPersistencePowerShell(opts)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "Persistence: "+err.Error())
		} else {
			snapshot.PersistenceItems = persistence
		}
	}

	sort.Slice(snapshot.Services, func(i, j int) bool {
		return strings.ToLower(snapshot.Services[i].Name) < strings.ToLower(snapshot.Services[j].Name)
	})
	sort.Slice(snapshot.ScheduledTasks, func(i, j int) bool {
		return strings.ToLower(snapshot.ScheduledTasks[i].Path) < strings.ToLower(snapshot.ScheduledTasks[j].Path)
	})
	sort.Slice(snapshot.StartupItems, func(i, j int) bool {
		if snapshot.StartupItems[i].Source == snapshot.StartupItems[j].Source {
			return strings.ToLower(snapshot.StartupItems[i].Name) < strings.ToLower(snapshot.StartupItems[j].Name)
		}
		return snapshot.StartupItems[i].Source < snapshot.StartupItems[j].Source
	})
	sort.Slice(snapshot.Users, func(i, j int) bool {
		return strings.ToLower(snapshot.Users[i].Name) < strings.ToLower(snapshot.Users[j].Name)
	})
	sort.Slice(snapshot.ImageHijacks, func(i, j int) bool {
		return strings.ToLower(snapshot.ImageHijacks[i].Image) < strings.ToLower(snapshot.ImageHijacks[j].Image)
	})
	sort.Slice(snapshot.PersistenceItems, func(i, j int) bool {
		if snapshot.PersistenceItems[i].Category == snapshot.PersistenceItems[j].Category {
			return strings.ToLower(snapshot.PersistenceItems[i].Name) < strings.ToLower(snapshot.PersistenceItems[j].Name)
		}
		return snapshot.PersistenceItems[i].Category < snapshot.PersistenceItems[j].Category
	})

	return snapshot, nil
}

func collectServicesLegacy(opts Options) ([]ServiceInfo, error) {
	if services, err := collectServicesPowerShellText(opts); err == nil && len(services) > 0 {
		return services, nil
	}
	return collectServicesWMIC(opts)
}

func collectServicesPowerShellText(opts Options) ([]ServiceInfo, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
function Clean-Text($value) {
  if ($null -eq $value) { '' } else { ([string]$value).Replace([string][char]9, ' ').Replace([string][char]13, ' ').Replace([string][char]10, ' ') }
}
Get-WmiObject -Class Win32_Service | ForEach-Object {
  @(
    (Clean-Text $_.Name),
    (Clean-Text $_.DisplayName),
    (Clean-Text $_.State),
    (Clean-Text $_.StartMode),
    (Clean-Text $_.StartName),
    (Clean-Text $_.PathName)
  ) -join ([string][char]9)
}
`
	cmd := winexec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(decodeCommandOutput(stderr.Bytes()))
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}

	var services []psService
	for _, line := range strings.Split(decodeCommandOutput(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 6 {
			continue
		}
		services = append(services, psService{
			Name:        strings.TrimSpace(parts[0]),
			DisplayName: strings.TrimSpace(parts[1]),
			State:       strings.TrimSpace(parts[2]),
			StartMode:   strings.TrimSpace(parts[3]),
			Account:     strings.TrimSpace(parts[4]),
			Command:     strings.TrimSpace(parts[5]),
		})
	}
	return servicesFromPS(services, opts), nil
}

func collectServicesWMIC(opts Options) ([]ServiceInfo, error) {
	cmd := winexec.Command("wmic.exe", "service", "get", "Name,DisplayName,State,StartMode,StartName,PathName", "/format:csv")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(decodeCommandOutput(out)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}

	header := records[0]
	index := make(map[string]int, len(header))
	for i, name := range header {
		index[strings.TrimSpace(name)] = i
	}
	get := func(record []string, name string) string {
		i, ok := index[name]
		if !ok || i < 0 || i >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[i])
	}

	var services []psService
	for _, record := range records[1:] {
		name := get(record, "Name")
		if name == "" {
			continue
		}
		services = append(services, psService{
			Name:        name,
			DisplayName: get(record, "DisplayName"),
			State:       get(record, "State"),
			StartMode:   get(record, "StartMode"),
			Account:     get(record, "StartName"),
			Command:     get(record, "PathName"),
		})
	}
	return servicesFromPS(services, opts), nil
}

func collectUsersLegacy() ([]UserInfo, error) {
	if users, err := collectUsersPowerShellText(); err == nil && len(users) > 0 {
		return users, nil
	}
	return collectUsersWMIC()
}

func collectUsersPowerShellText() ([]UserInfo, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
function Clean-Text($value) {
  if ($null -eq $value) { '' } else { ([string]$value).Replace([string][char]9, ' ').Replace([string][char]13, ' ').Replace([string][char]10, ' ') }
}
Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
  @(
    (Clean-Text $_.Name),
    (Clean-Text $_.SID),
    (Clean-Text $_.Disabled),
    (Clean-Text $_.Lockout),
    (Clean-Text $_.PasswordRequired),
    (Clean-Text $_.LocalAccount)
  ) -join ([string][char]9)
}
`
	cmd := winexec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(decodeCommandOutput(stderr.Bytes()))
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}

	var users []UserInfo
	for _, line := range strings.Split(decodeCommandOutput(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 6 {
			continue
		}
		users = append(users, UserInfo{
			Name:             strings.TrimSpace(parts[0]),
			SID:              strings.TrimSpace(parts[1]),
			Disabled:         parseWMICBool(parts[2]),
			Lockout:          parseWMICBool(parts[3]),
			PasswordRequired: parseWMICBool(parts[4]),
			LocalAccount:     parseWMICBool(parts[5]),
		})
	}
	return users, nil
}

func collectUsersWMIC() ([]UserInfo, error) {
	cmd := winexec.Command("wmic.exe", "useraccount", "where", "LocalAccount=True", "get", "Name,SID,Disabled,Lockout,PasswordRequired,LocalAccount", "/format:csv")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(decodeCommandOutput(out)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}

	header := records[0]
	index := make(map[string]int, len(header))
	for i, name := range header {
		index[strings.TrimSpace(name)] = i
	}
	get := func(record []string, name string) string {
		i, ok := index[name]
		if !ok || i < 0 || i >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[i])
	}

	users := make([]UserInfo, 0, len(records)-1)
	for _, record := range records[1:] {
		name := get(record, "Name")
		if name == "" {
			continue
		}
		users = append(users, UserInfo{
			Name:             name,
			SID:              get(record, "SID"),
			Disabled:         parseWMICBool(get(record, "Disabled")),
			Lockout:          parseWMICBool(get(record, "Lockout")),
			PasswordRequired: parseWMICBool(get(record, "PasswordRequired")),
			LocalAccount:     parseWMICBool(get(record, "LocalAccount")),
		})
	}
	return users, nil
}

func parseWMICBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "是":
		return true
	default:
		return false
	}
}

func collectStartupFallback(opts Options) ([]StartupItem, error) {
	var items []psStartupItem
	registryItems, regErr := collectStartupRegistryReg()
	items = append(items, registryItems...)
	items = append(items, collectStartupFoldersGo()...)
	if len(items) == 0 && regErr != nil {
		return nil, regErr
	}
	return startupFromPS(items, opts), nil
}

func collectStartupRegistryReg() ([]psStartupItem, error) {
	keys := []struct {
		source string
		path   string
	}{
		{"HKLM Run", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`},
		{"HKLM RunOnce", `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{"HKCU Run", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`},
		{"HKCU RunOnce", `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{"HKLM Wow6432 Run", `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`},
		{"HKLM Wow6432 RunOnce", `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`},
	}

	var items []psStartupItem
	var firstErr error
	for _, key := range keys {
		rows, err := queryRegValues(key.path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, row := range rows {
			items = append(items, psStartupItem{
				Source:   key.source,
				Name:     row.name,
				Command:  row.value,
				Location: key.path,
			})
		}
	}
	return items, firstErr
}

func collectStartupFoldersGo() []psStartupItem {
	var folders []struct {
		source string
		path   string
	}
	if appData := os.Getenv("APPDATA"); appData != "" {
		folders = append(folders, struct {
			source string
			path   string
		}{"User Startup", filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup`)})
	}
	if programData := os.Getenv("ProgramData"); programData != "" {
		folders = append(folders, struct {
			source string
			path   string
		}{"Common Startup", filepath.Join(programData, `Microsoft\Windows\Start Menu\Programs\Startup`)})
	}

	var items []psStartupItem
	for _, folder := range folders {
		if folder.path == "" {
			continue
		}
		entries, err := os.ReadDir(folder.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fullPath := filepath.Join(folder.path, entry.Name())
			items = append(items, psStartupItem{
				Source:   folder.source,
				Name:     entry.Name(),
				Command:  fullPath,
				Location: folder.path,
			})
		}
	}
	return items
}

func collectImageHijacksReg(opts Options) ([]ImageHijackInfo, error) {
	const root = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	cmd := winexec.Command("cmd.exe", "/U", "/C", "reg.exe", "query", root, "/s", "/v", "Debugger")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	var items []psImageHijack
	currentKey := ""
	for _, line := range strings.Split(decodeCommandOutput(out), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), "HKEY_") {
			currentKey = trimmed
			continue
		}
		row, ok := parseRegValueLine(line)
		if !ok || !strings.EqualFold(row.name, "Debugger") || row.value == "" || currentKey == "" {
			continue
		}
		items = append(items, psImageHijack{
			Image:        taskNameFromPath(currentKey),
			Debugger:     row.value,
			RegistryPath: currentKey,
		})
	}
	return hijacksFromPS(items, opts), nil
}

type regValue struct {
	name  string
	kind  string
	value string
}

func queryRegValues(path string) ([]regValue, error) {
	cmd := winexec.Command("cmd.exe", "/U", "/C", "reg.exe", "query", path)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var rows []regValue
	for _, line := range strings.Split(decodeCommandOutput(out), "\n") {
		row, ok := parseRegValueLine(line)
		if !ok {
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func parseRegValueLine(line string) (regValue, bool) {
	line = strings.TrimRight(line, "\r")
	if strings.TrimSpace(line) == "" {
		return regValue{}, false
	}
	if strings.HasPrefix(strings.TrimSpace(line), "HKEY_") {
		return regValue{}, false
	}
	parts := regexp.MustCompile(`\s{2,}`).Split(strings.TrimSpace(line), 3)
	if len(parts) < 3 || !strings.HasPrefix(strings.ToUpper(parts[1]), "REG_") {
		return regValue{}, false
	}
	return regValue{
		name:  strings.TrimSpace(parts[0]),
		kind:  strings.TrimSpace(parts[1]),
		value: strings.TrimSpace(parts[2]),
	}, true
}

func collectPowerShellSnapshot() (psSnapshot, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$ErrorActionPreference = 'SilentlyContinue'
function Get-WmiCompat($class, $filter) {
  if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    if ($filter) { return Get-CimInstance -ClassName $class -Filter $filter }
    return Get-CimInstance -ClassName $class
  }
  if ($filter) { return Get-WmiObject -Class $class -Filter $filter }
  return Get-WmiObject -Class $class
}
$services = Get-WmiCompat 'Win32_Service' '' | Select-Object Name,DisplayName,State,StartMode,StartName,PathName
$scheduledTasks = @()
try {
  $scheduledTasks = schtasks.exe /query /fo csv /v | ConvertFrom-Csv | Where-Object { $_.TaskName -and $_.TaskName -ne 'TaskName' } | ForEach-Object {
    [pscustomobject]@{
      Name=($_.TaskName -replace '^.*\\','')
      Path=$_.TaskName
      State=$_.'Scheduled Task State'
      Status=$_.Status
      Author=$_.Author
      Command=$_.'Task To Run'
    }
  }
} catch {}
$users = Get-WmiCompat 'Win32_UserAccount' "LocalAccount=True" | Select-Object Name,SID,Disabled,Lockout,PasswordRequired,LocalAccount
$startupRegistry = @()
$runKeys = @(
  @{Source='HKLM Run'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'},
  @{Source='HKLM RunOnce'; Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'},
  @{Source='HKCU Run'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'},
  @{Source='HKCU RunOnce'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'},
  @{Source='HKLM Wow6432 Run'; Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'},
  @{Source='HKLM Wow6432 RunOnce'; Path='HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'}
)
foreach ($key in $runKeys) {
  $props = Get-ItemProperty -Path $key.Path
  if ($props) {
    foreach ($prop in $props.PSObject.Properties) {
      if ($prop.Name -notmatch '^PS') {
        $startupRegistry += [pscustomobject]@{Source=$key.Source; Name=$prop.Name; Command=[string]$prop.Value; Location=$key.Path}
      }
    }
  }
}
$startupFolders = @()
$folders = @(
  @{Source='User Startup'; Path=[Environment]::GetFolderPath('Startup')},
  @{Source='Common Startup'; Path=[Environment]::GetFolderPath('CommonStartup')}
)
foreach ($folder in $folders) {
  if ($folder.Path -and (Test-Path $folder.Path)) {
    Get-ChildItem -LiteralPath $folder.Path | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
      $startupFolders += [pscustomobject]@{Source=$folder.Source; Name=$_.Name; Command=$_.FullName; Location=$folder.Path}
    }
  }
}
$imageHijacks = @()
$ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeoRoot) {
  Get-ChildItem -LiteralPath $ifeoRoot | ForEach-Object {
    $debugger = (Get-ItemProperty -LiteralPath $_.PSPath -Name Debugger).Debugger
    if ($debugger) {
      $imageHijacks += [pscustomobject]@{Image=$_.PSChildName; Debugger=[string]$debugger; RegistryPath=$_.Name}
    }
  }
}
$persistence = @()
function Add-Persistence($category, $name, $value, $location) {
  if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
    $script:persistence += [pscustomobject]@{Category=[string]$category; Name=[string]$name; Value=[string]$value; Location=[string]$location}
  }
}
$regChecks = @(
  @{Category='Winlogon'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Names=@('Shell','Userinit','Notify')},
  @{Category='AppInit_DLLs'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Names=@('AppInit_DLLs','LoadAppInit_DLLs')},
  @{Category='LSA'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Names=@('Authentication Packages','Security Packages','Notification Packages')},
  @{Category='KnownDLLs'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'; Names=$null}
)
foreach ($check in $regChecks) {
  $props = Get-ItemProperty -Path $check.Path
  if ($props) {
    foreach ($prop in $props.PSObject.Properties) {
      if ($prop.Name -match '^PS') { continue }
      if ($check.Names -and @($check.Names) -notcontains $prop.Name) { continue }
      Add-Persistence $check.Category $prop.Name (($prop.Value | Out-String).Trim()) $check.Path
    }
  }
}
$printRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
if (Test-Path $printRoot) {
  Get-ChildItem -LiteralPath $printRoot | ForEach-Object {
    $driver = (Get-ItemProperty -LiteralPath $_.PSPath -Name Driver).Driver
    Add-Persistence 'Print Monitor' $_.PSChildName $driver $_.Name
  }
}
try {
  Get-WmiObject -Namespace root\subscription -Class __EventFilter | ForEach-Object {
    Add-Persistence 'WMI EventFilter' $_.Name $_.Query $_.__RELPATH
  }
  Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | ForEach-Object {
    Add-Persistence 'WMI CommandConsumer' $_.Name $_.CommandLineTemplate $_.__RELPATH
  }
  Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer | ForEach-Object {
    Add-Persistence 'WMI ScriptConsumer' $_.Name $_.ScriptText $_.__RELPATH
  }
  Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | ForEach-Object {
    Add-Persistence 'WMI Binding' $_.Filter $_.Consumer $_.__RELPATH
  }
} catch {}
$browserDirs = @(
  @{Category='Chrome Extension Dir'; Path=(Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Extensions')},
  @{Category='Edge Extension Dir'; Path=(Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Extensions')},
  @{Category='Firefox Extension Dir'; Path=(Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles')}
)
foreach ($dir in $browserDirs) {
  if ($dir.Path -and (Test-Path $dir.Path)) {
    Get-ChildItem -LiteralPath $dir.Path -Directory | Select-Object -First 80 | ForEach-Object {
      Add-Persistence $dir.Category $_.Name $_.FullName $dir.Path
    }
  }
}
[pscustomobject]@{
  Services=@($services)
  ScheduledTasks=@($scheduledTasks)
  Users=@($users)
  StartupRegistry=@($startupRegistry)
  StartupFolders=@($startupFolders)
  ImageHijacks=@($imageHijacks)
  Persistence=@($persistence)
} | ConvertTo-Json -Compress -Depth 5
`

	cmd := winexec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return psSnapshot{}, errors.New(msg)
	}

	var snapshot psSnapshot
	if err := json.Unmarshal([]byte(decodeCommandOutput(out)), &snapshot); err != nil {
		return psSnapshot{}, err
	}
	return snapshot, nil
}

func servicesFromPS(items []psService, opts Options) []ServiceInfo {
	out := make([]ServiceInfo, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Command)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, ServiceInfo{
			Name:         item.Name,
			DisplayName:  item.DisplayName,
			State:        item.State,
			StartMode:    item.StartMode,
			Account:      item.Account,
			Command:      item.Command,
			Path:         path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func startupFromPS(items []psStartupItem, opts Options) []StartupItem {
	out := make([]StartupItem, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Command)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, StartupItem{
			Source:       item.Source,
			Name:         item.Name,
			Command:      item.Command,
			Location:     item.Location,
			Path:         path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func tasksFromPS(items []psTask, opts Options) []ScheduledTaskInfo {
	out := make([]ScheduledTaskInfo, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Command)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, ScheduledTaskInfo{
			Name:         item.Name,
			Path:         item.Path,
			State:        item.State,
			Status:       item.Status,
			Author:       item.Author,
			Command:      item.Command,
			Executable:   path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func hijacksFromPS(items []psImageHijack, opts Options) []ImageHijackInfo {
	out := make([]ImageHijackInfo, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Debugger)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, ImageHijackInfo{
			Image:        item.Image,
			Debugger:     item.Debugger,
			RegistryPath: item.RegistryPath,
			Path:         path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func persistenceFromPS(items []psPersistence, opts Options) []PersistenceInfo {
	out := make([]PersistenceInfo, 0, len(items))
	for _, item := range items {
		path := executablePathFromCommand(item.Value)
		md5, hashErr, sig := enrichExecutable(path, opts)
		out = append(out, PersistenceInfo{
			Category:     item.Category,
			Name:         item.Name,
			Value:        item.Value,
			Location:     item.Location,
			Path:         path,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}
	return out
}

func collectPersistencePowerShell(opts Options) ([]PersistenceInfo, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
function Is-Blank($value) {
  if ($null -eq $value) { return $true }
  return ([string]$value).Trim().Length -eq 0
}
function Clean($value) {
  if ($null -eq $value) { return '' }
  return ([string]$value).Replace([string][char]13, ' ').Replace([string][char]10, ' ')
}
function Encode($value) {
  return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Clean $value)))
}
function Add-Persistence($category, $name, $value, $location) {
  if (-not (Is-Blank $value)) {
    [Console]::Out.WriteLine('R|' + ((@($category, $name, $value, $location) | ForEach-Object { Encode $_ }) -join '|'))
  }
}
$regChecks = @(
  @{Category='Winlogon'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Names=@('Shell','Userinit','Notify')},
  @{Category='AppInit_DLLs'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Names=@('AppInit_DLLs','LoadAppInit_DLLs')},
  @{Category='LSA'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Names=@('Authentication Packages','Security Packages','Notification Packages')},
  @{Category='KnownDLLs'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'; Names=$null}
)
foreach ($check in $regChecks) {
  $props = Get-ItemProperty -Path $check.Path -ErrorAction SilentlyContinue
  if ($props) {
    foreach ($prop in $props.PSObject.Properties) {
      if ($prop.Name -match '^PS') { continue }
      if ($check.Names -and @($check.Names) -notcontains $prop.Name) { continue }
      Add-Persistence $check.Category $prop.Name (($prop.Value | Out-String).Trim()) $check.Path
    }
  }
}
$printRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
if (Test-Path $printRoot) {
  Get-ChildItem -LiteralPath $printRoot -ErrorAction SilentlyContinue | ForEach-Object {
    $driver = (Get-ItemProperty -LiteralPath $_.PSPath -Name Driver -ErrorAction SilentlyContinue).Driver
    Add-Persistence 'Print Monitor' $_.PSChildName $driver $_.Name
  }
}
try {
  Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop | ForEach-Object { Add-Persistence 'WMI EventFilter' $_.Name $_.Query $_.__RELPATH }
  Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { Add-Persistence 'WMI CommandConsumer' $_.Name $_.CommandLineTemplate $_.__RELPATH }
  Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { Add-Persistence 'WMI ScriptConsumer' $_.Name $_.ScriptText $_.__RELPATH }
  Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object { Add-Persistence 'WMI Binding' $_.Filter $_.Consumer $_.__RELPATH }
} catch {}
$browserDirs = @(
  @{Category='Chrome Extension Dir'; Path=(Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Extensions')},
  @{Category='Edge Extension Dir'; Path=(Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Extensions')},
  @{Category='Firefox Extension Dir'; Path=(Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles')}
)
foreach ($dir in $browserDirs) {
  if ($dir.Path -and (Test-Path $dir.Path)) {
    Get-ChildItem -LiteralPath $dir.Path -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Select-Object -First 80 | ForEach-Object {
      Add-Persistence $dir.Category $_.Name $_.FullName $dir.Path
    }
  }
}
`
	cmd := winexec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(decodeCommandOutput(stderr.Bytes()))
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	var items []psPersistence
	for _, line := range strings.Split(decodeCommandOutput(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 5 || parts[0] != "R" {
			continue
		}
		fields, err := decodeHostFields(parts[1:])
		if err != nil {
			continue
		}
		items = append(items, psPersistence{
			Category: fields[0],
			Name:     fields[1],
			Value:    fields[2],
			Location: fields[3],
		})
	}
	return persistenceFromPS(items, opts), nil
}

func decodeHostFields(values []string) ([]string, error) {
	out := make([]string, len(values))
	for i, value := range values {
		data, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
		out[i] = string(data)
	}
	return out, nil
}

func collectScheduledTasks(opts Options) ([]ScheduledTaskInfo, error) {
	if tasks, err := collectScheduledTasksCOM(opts); err == nil && len(tasks) > 0 {
		return tasks, nil
	}
	if tasks, err := collectSchtasksPowerShell(opts); err == nil && len(tasks) > 0 {
		return tasks, nil
	}
	if tasks, err := collectSchtasksCSV(opts); err == nil && len(tasks) > 0 {
		return tasks, nil
	}

	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("cannot resolve scheduled task root")
	}

	var tasks []ScheduledTaskInfo
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}

		item, err := parseScheduledTask(root, path, opts)
		if err == nil && item.Command != "" {
			tasks = append(tasks, item)
		}
		return nil
	})
	return tasks, err
}

func collectScheduledTasksCOM(opts Options) ([]ScheduledTaskInfo, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
function Convert-TaskState($state) {
  switch ($state) { 0 {'Unknown'} 1 {'Disabled'} 2 {'Queued'} 3 {'Ready'} 4 {'Running'} default {[string]$state} }
}
function Walk-Folder($folder) {
  foreach ($task in @($folder.GetTasks(0))) {
    foreach ($action in @($task.Definition.Actions)) {
      if ($action.Type -eq 0) {
        [pscustomobject]@{
          Name=$task.Name
          Path=$task.Path
          State=($(if ($task.Enabled) {'Enabled'} else {'Disabled'}))
          Status=(Convert-TaskState $task.State)
          Author=$task.Definition.RegistrationInfo.Author
          Command=(($action.Path + ' ' + $action.Arguments).Trim())
        }
      }
    }
  }
  foreach ($child in @($folder.GetFolders(0))) { Walk-Folder $child }
}
$schedule = New-Object -ComObject Schedule.Service
$schedule.Connect()
@((Walk-Folder ($schedule.GetFolder('\')))) | ConvertTo-Json -Compress -Depth 4
`
	cmd := winexec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}

	var tasks []psTask
	if err := unmarshalPSTaskList(out, &tasks); err != nil {
		return nil, err
	}
	return tasksFromPS(tasks, opts), nil
}

func collectSchtasksPowerShell(opts Options) ([]ScheduledTaskInfo, error) {
	script := `
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$tasks = schtasks.exe /query /fo csv /v | ConvertFrom-Csv | Where-Object { $_.TaskName -and $_.TaskName -ne 'TaskName' } | ForEach-Object {
  [pscustomobject]@{
    Name=($_.TaskName -replace '^.*\\','')
    Path=$_.TaskName
    State=$_.'Scheduled Task State'
    Status=$_.Status
    Author=$_.Author
    Command=$_.'Task To Run'
  }
}
@($tasks) | ConvertTo-Json -Compress -Depth 4
`
	cmd := winexec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}

	var tasks []psTask
	if err := unmarshalPSTaskList(out, &tasks); err != nil {
		return nil, err
	}
	return tasksFromPS(tasks, opts), nil
}

func unmarshalPSTaskList(raw []byte, out *[]psTask) error {
	data := bytes.TrimSpace([]byte(decodeCommandOutput(raw)))
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '[' {
		return json.Unmarshal(data, out)
	}
	var one psTask
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*out = []psTask{one}
	return nil
}

func collectSchtasksCSV(opts Options) ([]ScheduledTaskInfo, error) {
	cmd := winexec.Command("schtasks.exe", "/query", "/fo", "csv", "/v")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(decodeCommandOutput(out)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}

	header := records[0]
	index := make(map[string]int, len(header))
	for i, name := range header {
		index[name] = i
	}

	get := func(record []string, name string) string {
		i, ok := index[name]
		if !ok || i < 0 || i >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[i])
	}

	tasks := make([]ScheduledTaskInfo, 0, len(records)-1)
	for _, record := range records[1:] {
		taskPath := get(record, "TaskName")
		if taskPath == "" || taskPath == "TaskName" {
			continue
		}

		command := get(record, "Task To Run")
		executable := executablePathFromCommand(command)
		md5, hashErr, sig := enrichExecutable(executable, opts)
		tasks = append(tasks, ScheduledTaskInfo{
			Name:         taskNameFromPath(taskPath),
			Path:         taskPath,
			State:        get(record, "Scheduled Task State"),
			Status:       get(record, "Status"),
			Author:       get(record, "Author"),
			Command:      command,
			Executable:   executable,
			MD5:          md5,
			Signature:    sig.Status,
			SignatureMsg: sig.Message,
			HashError:    hashErr,
		})
	}

	return tasks, nil
}

func taskNameFromPath(path string) string {
	path = strings.TrimRight(path, `\`)
	if path == "" {
		return ""
	}
	if idx := strings.LastIndex(path, `\`); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func parseScheduledTask(root, path string, opts Options) (ScheduledTaskInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ScheduledTaskInfo{}, err
	}

	text := decodeTaskXML(raw)
	var task taskXML
	if err := xml.Unmarshal([]byte(text), &task); err != nil {
		return ScheduledTaskInfo{}, err
	}
	if len(task.Actions.Exec) == 0 {
		return ScheduledTaskInfo{}, nil
	}

	rel, _ := filepath.Rel(root, path)
	taskPath := `\` + strings.ReplaceAll(rel, string(os.PathSeparator), `\`)
	execAction := task.Actions.Exec[0]
	executable := executablePathFromCommand(execAction.Command)
	if executable == "" {
		executable = executablePathFromCommand(execAction.Command + " " + execAction.Arguments)
	}
	md5, hashErr, sig := enrichExecutable(executable, opts)

	return ScheduledTaskInfo{
		Name:         filepath.Base(path),
		Path:         taskPath,
		State:        "",
		Status:       "",
		Author:       task.RegistrationInfo.Author,
		Command:      execAction.Command,
		Arguments:    execAction.Arguments,
		Executable:   executable,
		MD5:          md5,
		Signature:    sig.Status,
		SignatureMsg: sig.Message,
		HashError:    hashErr,
	}, nil
}

func decodeTaskXML(raw []byte) string {
	if len(raw) >= 2 {
		if raw[0] == 0xff && raw[1] == 0xfe {
			u16 := make([]uint16, 0, (len(raw)-2)/2)
			for i := 2; i+1 < len(raw); i += 2 {
				u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
			}
			return string(utf16.Decode(u16))
		}
		if raw[0] == 0xfe && raw[1] == 0xff {
			u16 := make([]uint16, 0, (len(raw)-2)/2)
			for i := 2; i+1 < len(raw); i += 2 {
				u16 = append(u16, uint16(raw[i])<<8|uint16(raw[i+1]))
			}
			return string(utf16.Decode(u16))
		}
	}
	return string(raw)
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

func enrichExecutable(path string, opts Options) (string, string, process.SignatureResult) {
	if path == "" {
		return "", "", process.SignatureResult{}
	}

	md5, hashErr := process.HashFileMD5(path, opts.HashLimitBytes)
	return md5, hashErr, process.CheckSignature(path)
}

func executablePathFromCommand(command string) string {
	command = strings.TrimSpace(expandWindowsEnv(command))
	if command == "" {
		return ""
	}

	command = strings.TrimPrefix(command, `\??\`)
	command = strings.TrimPrefix(command, `\\?\`)
	if isNonExecutableCommand(command) {
		return ""
	}

	if strings.HasPrefix(command, `"`) || strings.HasPrefix(command, `'`) {
		quote := command[0]
		if end := strings.IndexByte(command[1:], quote); end >= 0 {
			return normalizeExecutablePath(command[1:end+1], true)
		}
	}

	first := strings.Fields(command)
	if len(first) > 0 {
		if path := normalizeExecutablePath(first[0], false); path != "" {
			return path
		}
	}

	lower := strings.ToLower(command)
	for i := 0; i < len(lower); i++ {
		for _, ext := range executableExtensions {
			if strings.HasPrefix(lower[i:], ext) && isExecutableExtensionBoundary(command, i+len(ext)) {
				return normalizeExecutablePath(strings.TrimSpace(command[:i+len(ext)]), true)
			}
		}
	}

	return ""
}

var executableExtensions = []string{".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}

func isNonExecutableCommand(command string) bool {
	switch strings.ToLower(strings.Trim(command, `" '	`)) {
	case "com handler", "custom handler", "multiple actions", "n/a", "not available", "none", "null":
		return true
	default:
		return false
	}
}

func isExecutableExtensionBoundary(command string, end int) bool {
	if end >= len(command) {
		return true
	}
	switch command[end] {
	case ' ', '\t', '\r', '\n', '"', '\'', ',', ';':
		return true
	default:
		return false
	}
}

var percentEnvPattern = regexp.MustCompile(`%([^%]+)%`)

func expandWindowsEnv(value string) string {
	return percentEnvPattern.ReplaceAllStringFunc(value, func(match string) string {
		name := strings.Trim(match, "%")
		if expanded := os.Getenv(name); expanded != "" {
			return expanded
		}
		return match
	})
}

func normalizeExecutablePath(path string, keepMissingAbsolute bool) string {
	path = strings.Trim(path, `" '	`)
	if path == "" {
		return ""
	}
	path = strings.TrimPrefix(path, `\??\`)
	path = strings.TrimPrefix(path, `\\?\`)
	if strings.HasPrefix(strings.ToLower(path), "system32\\") {
		path = filepath.Join(os.Getenv("SystemRoot"), path)
	}
	if strings.HasPrefix(strings.ToLower(path), "syswow64\\") {
		path = filepath.Join(os.Getenv("SystemRoot"), path)
	}

	if filepath.IsAbs(path) {
		clean := filepath.Clean(path)
		if info, err := os.Stat(clean); err == nil {
			if info.IsDir() {
				return ""
			}
			return clean
		}
		if keepMissingAbsolute {
			return clean
		}
		return ""
	}

	if candidate, err := exec.LookPath(path); err == nil {
		if clean, err := filepath.Abs(candidate); err == nil {
			return clean
		}
		return candidate
	}
	return ""
}

func (s Snapshot) Summary() string {
	return fmt.Sprintf("services=%d tasks=%d startup=%d users=%d ifeo=%d persistence=%d", len(s.Services), len(s.ScheduledTasks), len(s.StartupItems), len(s.Users), len(s.ImageHijacks), len(s.PersistenceItems))
}
