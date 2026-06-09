//go:build windows

package securitylog

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

const (
	eventFieldLimit      = 900
	eventDetailPartLimit = 220
	powershellFieldLimit = 260
)

func Collect(opts Options) (Snapshot, error) {
	maxRecords := opts.MaxRecords
	if maxRecords <= 0 {
		maxRecords = 500
	}
	if maxRecords > 5000 {
		maxRecords = 5000
	}

	wevtSnapshot, err := collectWevtutilSnapshot(opts, maxRecords)
	if err == nil {
		wevtSnapshot.CollectionErrors = localizeErrors(wevtSnapshot.CollectionErrors)
		return wevtSnapshot, nil
	}
	return Snapshot{
		CollectionErrors: localizeErrors([]string{"事件日志: " + err.Error()}),
		GeneratedAt:      time.Now().Format("2006-01-02 15:04:05"),
	}, nil

	startRaw := psDateLiteral(opts.StartTime)
	endRaw := psDateLiteral(opts.EndTime)

	script := fmt.Sprintf(`
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$max = %d
$startTimeRaw = %q
$endTimeRaw = %q
$startTime = if ([string]::IsNullOrWhiteSpace($startTimeRaw)) { $null } else { [datetime]::ParseExact($startTimeRaw, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
$endTime = if ([string]::IsNullOrWhiteSpace($endTimeRaw)) { $null } else { [datetime]::ParseExact($endTimeRaw, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
$events = @()
$errors = @()

function New-EventFilter($logName, $ids) {
  $filter = @{ LogName = $logName }
  if ($null -ne $ids) { $filter.Id = $ids }
  if ($null -ne $startTime) { $filter.StartTime = $startTime }
  if ($null -ne $endTime) { $filter.EndTime = $endTime }
  return $filter
}

function Add-Error($source, $message) {
  $script:errors += ([string]$source + ': ' + [string]$message)
}

function Clean-Value($value) {
  if ($null -eq $value) { return '' }
  $text = [string]$value
  if ([string]::IsNullOrWhiteSpace($text) -or $text -eq '-') { return '' }
  return $text
}

function Get-EventMessage($event) {
  try {
    return (([string]$event.FormatDescription()) -replace '\r?\n', ' ')
  } catch {
    return ''
  }
}

function Get-EventDataMap($event) {
  $map = @{}
  try {
    [xml]$xml = $event.ToXml()
    $idx = 1
    foreach ($item in @($xml.Event.EventData.Data)) {
      $name = Clean-Value $item.Name
      if ($name -eq '') { $name = 'Param' + $idx }
      $map[$name] = Clean-Value $item.'#text'
      $idx++
    }
    foreach ($container in @($xml.Event.UserData.ChildNodes)) {
      foreach ($node in @($container.ChildNodes)) {
        if ($node.NodeType -eq 'Element') {
          $map[$node.Name] = Clean-Value $node.InnerText
        }
      }
    }
  } catch {}
  return $map
}

function First-Value($data, $names) {
  foreach ($name in @($names)) {
    if ($data.ContainsKey($name)) {
      $value = Clean-Value $data[$name]
      if ($value -ne '') { return $value }
    }
  }
  return ''
}

function Convert-LogonTypeName($value) {
  switch ([string]$value) {
    '2' { return '交互式登录' }
    '3' { return '网络登录' }
    '4' { return '批处理登录' }
    '5' { return '服务登录' }
    '7' { return '解锁' }
    '8' { return '网络明文登录' }
    '9' { return '新凭据登录' }
    '10' { return '远程交互式登录/RDP' }
    '11' { return '缓存交互式登录' }
    default { if ([string]::IsNullOrWhiteSpace([string]$value)) { return '' }; return ('LogonType ' + [string]$value) }
  }
}

function Convert-SecurityAction($eventId, $logonType) {
  switch ([int]$eventId) {
    4624 { if ([string]$logonType -eq '10') { return 'RDP 登录成功' }; return '登录成功' }
    4625 { if ([string]$logonType -eq '10') { return 'RDP 登录失败' }; return '登录失败' }
    4634 { return '注销' }
    4647 { return '用户主动注销' }
    4672 { return '特权登录' }
    4720 { return '用户创建' }
    4722 { return '用户启用' }
    4723 { return '尝试修改密码' }
    4724 { return '密码重置' }
    4725 { return '用户禁用' }
    4726 { return '用户删除' }
    4738 { return '用户属性变更' }
    4728 { return '添加到全局组' }
    4729 { return '从全局组移除' }
    4732 { return '添加到本地组' }
    4733 { return '从本地组移除' }
    4756 { return '添加到通用组' }
    4757 { return '从通用组移除' }
    4778 { return 'RDP 会话重新连接' }
    4779 { return 'RDP 会话断开' }
    4800 { return '工作站锁定' }
    4801 { return '工作站解锁' }
    default { return ('安全事件 ' + [string]$eventId) }
  }
}

function Convert-SecurityCategory($eventId, $logonType) {
  switch ([int]$eventId) {
    4624 { if ([string]$logonType -eq '10') { return 'RDP登录' }; return '登录' }
    4625 { if ([string]$logonType -eq '10') { return 'RDP登录' }; return '登录失败' }
    4634 { return '注销' }
    4647 { return '注销' }
    4672 { return '特权登录' }
    4778 { return 'RDP连接' }
    4779 { return 'RDP连接' }
    4800 { return '工作站锁定' }
    4801 { return '工作站解锁' }
    default { return '用户账户' }
  }
}

function Convert-RDPAction($eventId) {
  switch ([int]$eventId) {
    21 { return 'RDP 会话登录' }
    22 { return 'RDP Shell 启动' }
    23 { return 'RDP 会话注销' }
    24 { return 'RDP 会话断开' }
    25 { return 'RDP 会话重新连接' }
    39 { return 'RDP 会话断开' }
    40 { return 'RDP 会话状态变更' }
    1149 { return 'RDP 认证成功' }
    default { return ('RDP 事件 ' + [string]$eventId) }
  }
}

function Convert-PowerShellAction($eventId) {
  switch ([int]$eventId) {
    400 { return 'PowerShell 引擎启动' }
    403 { return 'PowerShell 引擎停止' }
    600 { return 'PowerShell Provider 加载' }
    800 { return 'PowerShell 管道执行' }
    4103 { return 'PowerShell 模块日志' }
    4104 { return 'PowerShell 脚本块日志' }
    4105 { return 'PowerShell 脚本块开始' }
    4106 { return 'PowerShell 脚本块结束' }
    default { return ('PowerShell 事件 ' + [string]$eventId) }
  }
}

function Add-Event($category, $source, $event, $data, $action, $account, $domain, $subject, $logonType, $sourceIp, $sourcePort, $workstation, $process, $serviceName, $command, $authPackage, $status, $failureReason, $targetSid, $details) {
  $message = Get-EventMessage $event
  $script:events += [pscustomobject]@{
    Time=$event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    Category=Clean-Value $category
    Source=Clean-Value $source
    EventID=[string]$event.Id
    Action=Clean-Value $action
    Account=Clean-Value $account
    Domain=Clean-Value $domain
    Subject=Clean-Value $subject
    LogonType=Clean-Value $logonType
    LogonTypeName=(Convert-LogonTypeName $logonType)
    SourceIP=Clean-Value $sourceIp
    SourcePort=Clean-Value $sourcePort
    Workstation=Clean-Value $workstation
    Process=Clean-Value $process
    ServiceName=Clean-Value $serviceName
    Command=Clean-Value $command
    AuthPackage=Clean-Value $authPackage
    Status=Clean-Value $status
    FailureReason=Clean-Value $failureReason
    TargetSID=Clean-Value $targetSid
    Provider=Clean-Value $event.ProviderName
    Level=Clean-Value $event.LevelDisplayName
    Message=Clean-Value $message
    Details=Clean-Value $details
  }
}

$canReadSecurity = $true
try {
  $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
} catch {
  Add-Error '安全日志' ('无法读取 Security 日志: ' + $_.Exception.Message)
  $canReadSecurity = $false
}

if ($canReadSecurity) {
  try {
    Get-WinEvent -FilterHashtable (New-EventFilter 'Security' @(4624,4625,4634,4647,4672,4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4756,4757,4778,4779,4800,4801)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
      $data = Get-EventDataMap $_
      $logonType = First-Value $data @('LogonType')
      $account = First-Value $data @('TargetUserName','AccountName')
      $domain = First-Value $data @('TargetDomainName','AccountDomain')
      $subject = (First-Value $data @('SubjectDomainName')) + '\' + (First-Value $data @('SubjectUserName'))
      if ($subject -eq '\') { $subject = '' }
      $sourceIp = First-Value $data @('IpAddress','ClientAddress','SourceNetworkAddress')
      $sourcePort = First-Value $data @('IpPort','ClientPort','SourcePort')
      $workstation = First-Value $data @('WorkstationName','ClientName','Workstation')
      $process = First-Value $data @('ProcessName','ProcessId')
      $authPackage = First-Value $data @('AuthenticationPackageName','PackageName')
      $status = First-Value $data @('Status','SubStatus')
      $failureReason = First-Value $data @('FailureReason')
      $sid = First-Value $data @('TargetUserSid','SubjectUserSid')
      $details = @()
      $memberName = First-Value $data @('MemberName')
      $groupName = First-Value $data @('TargetSid','GroupName')
      if ($memberName -ne '') { $details += ('成员=' + $memberName) }
      if ($groupName -ne '') { $details += ('组/SID=' + $groupName) }
      if ($data.ContainsKey('ElevatedToken')) { $details += ('ElevatedToken=' + $data['ElevatedToken']) }
      Add-Event (Convert-SecurityCategory $_.Id $logonType) 'Security' $_ $data (Convert-SecurityAction $_.Id $logonType) $account $domain $subject $logonType $sourceIp $sourcePort $workstation $process '' '' $authPackage $status $failureReason $sid ($details -join '; ')
    }
  } catch {
    Add-Error '安全日志' $_.Exception.Message
  }
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' @(1149)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $account = First-Value $data @('Param1','User','UserName')
    $domain = First-Value $data @('Param2','Domain')
    $sourceIp = First-Value $data @('Param3','Address','SourceNetworkAddress')
    Add-Event 'RDP连接' 'TerminalServices RemoteConnectionManager' $_ $data (Convert-RDPAction $_.Id) $account $domain '' '10' $sourceIp '' '' '' '' '' '' '' '' '' ''
  }
} catch {
  Add-Error 'RDP连接' $_.Exception.Message
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' @(21,22,23,24,25,39,40)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $account = First-Value $data @('User','Param1','TargetUser')
    $sourceIp = First-Value $data @('Address','Param3','SourceNetworkAddress')
    $details = @()
    $sessionId = First-Value $data @('SessionID','SessionId','Param2')
    if ($sessionId -ne '') { $details += ('SessionID=' + $sessionId) }
    Add-Event 'RDP连接' 'TerminalServices LocalSessionManager' $_ $data (Convert-RDPAction $_.Id) $account '' '' '10' $sourceIp '' '' '' '' '' '' '' '' '' ($details -join '; ')
  }
} catch {
  Add-Error 'RDP会话' $_.Exception.Message
}

try {
  Get-WinEvent -FilterHashtable (New-EventFilter 'System' @(7045)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
    $data = Get-EventDataMap $_
    $serviceName = First-Value $data @('ServiceName','param1','Param1')
    $imagePath = First-Value $data @('ImagePath','ServiceFileName','param2','Param2')
    $account = First-Value $data @('AccountName','ServiceAccount','param5','Param5')
    $details = @()
    $serviceType = First-Value $data @('ServiceType','param3','Param3')
    $startType = First-Value $data @('StartType','ServiceStartType','param4','Param4')
    if ($serviceType -ne '') { $details += ('服务类型=' + $serviceType) }
    if ($startType -ne '') { $details += ('启动类型=' + $startType) }
    Add-Event '服务创建' 'System/Service Control Manager' $_ $data '服务创建' $account '' '' '' '' '' '' '' $serviceName $imagePath '' '' '' '' ($details -join '; ')
  }
} catch {
  Add-Error '服务创建' $_.Exception.Message
}

foreach ($psLog in @('Microsoft-Windows-PowerShell/Operational','Windows PowerShell')) {
  try {
    Get-WinEvent -FilterHashtable (New-EventFilter $psLog @(400,403,600,800,4103,4104,4105,4106)) -MaxEvents $max -ErrorAction Stop | ForEach-Object {
      $data = Get-EventDataMap $_
      $command = First-Value $data @('ScriptBlockText','CommandLine','Payload','ContextInfo','HostApplication','Path','Param1')
      $account = First-Value $data @('UserId','User')
      Add-Event 'PowerShell日志' $psLog $_ $data (Convert-PowerShellAction $_.Id) $account '' '' '' '' '' '' 'powershell.exe' '' $command '' '' '' '' ''
    }
  } catch {
    Add-Error 'PowerShell日志' ($psLog + ': ' + $_.Exception.Message)
  }
}

$sqlServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(MSSQLSERVER|MSSQL\$|SQLSERVERAGENT|SQLAgent\$)' -or $_.DisplayName -match 'SQL Server' })
if ($sqlServices.Count -eq 0) {
  Add-Error 'SQL Server' '该系统未安装 SQL Server 或未发现 SQL Server 服务，因此没有 SQL Server 日志可分析。'
} else {
  try {
    $sqlEvents = @(Get-WinEvent -FilterHashtable (New-EventFilter 'Application' $null) -MaxEvents ($max * 5) -ErrorAction Stop | Where-Object { $_.ProviderName -match 'MSSQL|SQLSERVERAGENT|SQLAgent|SQL Server' } | Select-Object -First $max)
    if ($sqlEvents.Count -eq 0) {
      Add-Error 'SQL Server' '已发现 SQL Server 服务，但 Application 日志中未找到 SQL Server 事件。'
    }
    foreach ($event in $sqlEvents) {
      $data = Get-EventDataMap $event
      $instance = First-Value $data @('InstanceName','ServerName','Param1')
      Add-Event 'SQL Server日志' 'Application/SQL Server' $event $data 'SQL Server 事件' $instance '' '' '' '' '' '' '' '' '' '' '' '' '' ''
    }
  } catch {
    Add-Error 'SQL Server' $_.Exception.Message
  }
}

$ordered = @($events | Sort-Object @{Expression={ if ($_.Time) { $_.Time } else { '0000' } }; Descending=$true})
[pscustomobject]@{
  Events=@($ordered)
  CollectionErrors=@($errors)
  GeneratedAt=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
} | ConvertTo-Json -Compress -Depth 5
`, maxRecords, startRaw, endRaw)

	cmd := winexec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return Snapshot{}, errors.New(msg)
	}

	data := bytes.TrimPrefix(bytes.TrimSpace(out), []byte{0xEF, 0xBB, 0xBF})
	if len(data) == 0 {
		return Snapshot{}, errors.New("empty event log collection output")
	}

	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, err
	}
	snapshot.CollectionErrors = localizeErrors(snapshot.CollectionErrors)
	return snapshot, nil
}

type wevtQuery struct {
	logName  string
	source   string
	category string
	ids      []int
	limit    int
}

type wevtEvents struct {
	Events []wevtEvent `xml:"Event"`
}

type wevtEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID string `xml:"EventID"`
		Level   string `xml:"Level"`
		Time    struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []wevtData `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Nodes []xmlNode `xml:",any"`
	} `xml:"UserData"`
}

type wevtData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type xmlNode struct {
	XMLName  xml.Name
	Text     string    `xml:",chardata"`
	Children []xmlNode `xml:",any"`
}

func collectWevtutilSnapshot(opts Options, maxRecords int) (Snapshot, error) {
	snapshot := Snapshot{GeneratedAt: time.Now().Format("2006-01-02 15:04:05")}
	queries := []wevtQuery{
		{
			logName:  "Security",
			source:   "Security",
			category: "安全日志",
			ids:      []int{4624, 4625, 4634, 4647, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4756, 4757, 4778, 4779, 4800, 4801},
			limit:    maxRecords,
		},
		{
			logName:  "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
			source:   "TerminalServices RemoteConnectionManager",
			category: "RDP连接",
			ids:      []int{1149},
			limit:    maxRecords,
		},
		{
			logName:  "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
			source:   "TerminalServices LocalSessionManager",
			category: "RDP连接",
			ids:      []int{21, 22, 23, 24, 25, 39, 40},
			limit:    maxRecords,
		},
		{
			logName:  "System",
			source:   "System/Service Control Manager",
			category: "服务创建",
			ids:      []int{7045},
			limit:    maxRecords,
		},
		{
			logName:  "Microsoft-Windows-PowerShell/Operational",
			source:   "Microsoft-Windows-PowerShell/Operational",
			category: "PowerShell日志",
			ids:      []int{400, 403, 600, 800, 4103, 4104, 4105, 4106},
			limit:    maxRecords,
		},
		{
			logName:  "Windows PowerShell",
			source:   "Windows PowerShell",
			category: "PowerShell日志",
			ids:      []int{400, 403, 600, 800, 4103, 4104, 4105, 4106},
			limit:    maxRecords,
		},
	}

	for _, query := range queries {
		events, err := queryWevtutil(query, opts)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, query.category+": "+err.Error())
			continue
		}
		for _, event := range events {
			snapshot.Events = append(snapshot.Events, eventFromWevt(event, query))
		}
	}

	sqlInstalled, sqlErr := detectSQLServerInstalled()
	if sqlErr != nil {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "SQL Server: "+sqlErr.Error())
	} else if !sqlInstalled {
		snapshot.CollectionErrors = append(snapshot.CollectionErrors, "SQL Server: 该系统未安装 SQL Server 或未发现 SQL Server 服务，因此没有 SQL Server 日志可分析。")
	} else {
		events, err := queryWevtutil(wevtQuery{
			logName:  "Application",
			source:   "Application/SQL Server",
			category: "SQL Server日志",
			limit:    maxRecords * 5,
		}, opts)
		if err != nil {
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "SQL Server: "+err.Error())
		} else {
			count := 0
			for _, event := range events {
				if !strings.Contains(strings.ToLower(event.System.Provider.Name), "sql") && !strings.Contains(strings.ToLower(event.System.Provider.Name), "mssql") {
					continue
				}
				snapshot.Events = append(snapshot.Events, eventFromWevt(event, wevtQuery{source: "Application/SQL Server", category: "SQL Server日志"}))
				count++
				if count >= maxRecords {
					break
				}
			}
			if count == 0 {
				snapshot.CollectionErrors = append(snapshot.CollectionErrors, "SQL Server: 已发现 SQL Server 服务，但 Application 日志中未找到 SQL Server 事件。")
			}
		}
	}

	sort.SliceStable(snapshot.Events, func(i, j int) bool {
		return snapshot.Events[i].Time > snapshot.Events[j].Time
	})
	return snapshot, nil
}

func queryWevtutil(query wevtQuery, opts Options) ([]wevtEvent, error) {
	limit := query.limit
	if limit <= 0 {
		limit = 500
	}
	xpath := buildWevtutilXPath(query.ids, opts)
	cmd := winexec.Command("wevtutil.exe", "qe", query.logName, "/q:"+xpath, "/f:xml", "/c:"+strconv.Itoa(limit), "/rd:true")
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

	text := strings.TrimSpace(decodeCommandOutput(out))
	if text == "" {
		return nil, nil
	}
	text = strings.ReplaceAll(text, `<?xml version="1.0" encoding="utf-16"?>`, "")
	text = strings.ReplaceAll(text, `<?xml version="1.0" encoding="utf-8"?>`, "")
	text = strings.ReplaceAll(text, `<?xml version="1.0"?>`, "")
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ToValidUTF8(text, "")
	wrapped := "<Events>" + text + "</Events>"
	var parsed wevtEvents
	if err := xml.Unmarshal([]byte(wrapped), &parsed); err != nil {
		return nil, err
	}
	return parsed.Events, nil
}

func buildWevtutilXPath(ids []int, opts Options) string {
	var predicates []string
	if len(ids) > 0 {
		idParts := make([]string, 0, len(ids))
		for _, id := range ids {
			idParts = append(idParts, "EventID="+strconv.Itoa(id))
		}
		predicates = append(predicates, "("+strings.Join(idParts, " or ")+")")
	}
	if !opts.StartTime.IsZero() || !opts.EndTime.IsZero() {
		var timeParts []string
		if !opts.StartTime.IsZero() {
			timeParts = append(timeParts, "@SystemTime>='"+opts.StartTime.UTC().Format("2006-01-02T15:04:05.000Z")+"'")
		}
		if !opts.EndTime.IsZero() {
			timeParts = append(timeParts, "@SystemTime<='"+opts.EndTime.UTC().Format("2006-01-02T15:04:05.000Z")+"'")
		}
		predicates = append(predicates, "TimeCreated["+strings.Join(timeParts, " and ")+"]")
	}
	if len(predicates) == 0 {
		return "*"
	}
	return "*[System[" + strings.Join(predicates, " and ") + "]]"
}

func eventFromWevt(event wevtEvent, query wevtQuery) Event {
	data := eventDataMap(event)
	eventID := strings.TrimSpace(event.System.EventID)
	logonType := firstValue(data, "LogonType")
	source := query.source
	if source == "" {
		source = query.logName
	}
	category := query.category
	action := "事件 " + eventID
	account := ""
	domain := ""
	subject := ""
	sourceIP := ""
	sourcePort := ""
	workstation := ""
	processName := ""
	serviceName := ""
	command := ""
	authPackage := ""
	status := ""
	failureReason := ""
	targetSID := ""
	details := ""

	switch category {
	case "安全日志":
		category = securityCategory(eventID, logonType)
		action = securityAction(eventID, logonType)
		account = firstValue(data, "TargetUserName", "AccountName")
		domain = firstValue(data, "TargetDomainName", "AccountDomain")
		subjectDomain := firstValue(data, "SubjectDomainName")
		subjectUser := firstValue(data, "SubjectUserName")
		if subjectDomain != "" || subjectUser != "" {
			subject = strings.Trim(subjectDomain+`\`+subjectUser, `\`)
		}
		sourceIP = firstValue(data, "IpAddress", "ClientAddress", "SourceNetworkAddress")
		sourcePort = firstValue(data, "IpPort", "ClientPort", "SourcePort")
		workstation = firstValue(data, "WorkstationName", "ClientName", "Workstation")
		processName = firstValue(data, "ProcessName", "ProcessId")
		authPackage = firstValue(data, "AuthenticationPackageName", "PackageName")
		status = firstValue(data, "Status", "SubStatus")
		failureReason = firstValue(data, "FailureReason")
		targetSID = firstValue(data, "TargetUserSid", "SubjectUserSid")
		details = joinDetails(data, "MemberName", "GroupName", "TargetSid", "ElevatedToken")
	case "RDP连接":
		action = rdpAction(eventID)
		account = firstValue(data, "Param1", "User", "UserName", "TargetUser")
		domain = firstValue(data, "Param2", "Domain")
		sourceIP = firstValue(data, "Param3", "Address", "SourceNetworkAddress")
		logonType = "10"
		details = joinDetails(data, "SessionID", "SessionId", "Param2")
	case "服务创建":
		action = "服务创建"
		serviceName = firstValue(data, "ServiceName", "param1", "Param1")
		command = firstValue(data, "ImagePath", "ServiceFileName", "param2", "Param2")
		account = firstValue(data, "AccountName", "ServiceAccount", "param5", "Param5")
		details = joinDetails(data, "ServiceType", "param3", "Param3", "StartType", "ServiceStartType", "param4", "Param4")
	case "PowerShell日志":
		action = powershellAction(eventID)
		account = firstValue(data, "UserId", "User")
		processName = "powershell.exe"
		command = firstValue(data, "ScriptBlockText", "CommandLine", "Payload", "ContextInfo", "HostApplication", "Path", "Param1")
	case "SQL Server日志":
		action = "SQL Server 事件"
		account = firstValue(data, "InstanceName", "ServerName", "Param1")
		details = detailsFromMap(data, 6)
	default:
		details = detailsFromMap(data, 6)
	}

	if details == "" {
		details = detailsFromMap(data, 6)
	}
	if category == "PowerShell日志" {
		command = compactEventText(command, powershellFieldLimit)
		details = compactEventText(details, powershellFieldLimit)
	}

	return Event{
		Time:          formatEventTime(event.System.Time.SystemTime),
		Category:      cleanValue(category),
		Source:        cleanValue(source),
		EventID:       eventID,
		Action:        cleanValue(action),
		Account:       cleanValue(account),
		Domain:        cleanValue(domain),
		Subject:       cleanValue(subject),
		LogonType:     cleanValue(logonType),
		LogonTypeName: logonTypeName(logonType),
		SourceIP:      cleanValue(sourceIP),
		SourcePort:    cleanValue(sourcePort),
		Workstation:   cleanValue(workstation),
		Process:       cleanValue(processName),
		ServiceName:   cleanValue(serviceName),
		Command:       compactEventText(command, eventFieldLimit),
		AuthPackage:   cleanValue(authPackage),
		Status:        cleanValue(status),
		FailureReason: cleanValue(failureReason),
		TargetSID:     cleanValue(targetSID),
		Provider:      cleanValue(event.System.Provider.Name),
		Level:         levelName(event.System.Level),
		Details:       compactEventText(details, eventFieldLimit),
	}
}

func eventDataMap(event wevtEvent) map[string]string {
	out := make(map[string]string)
	for i, item := range event.EventData.Data {
		name := cleanValue(item.Name)
		if name == "" {
			name = "Param" + strconv.Itoa(i+1)
		}
		if value := cleanValue(item.Value); value != "" {
			out[name] = value
		}
	}
	for _, node := range event.UserData.Nodes {
		flattenXMLNode(out, node)
	}
	return out
}

func flattenXMLNode(out map[string]string, node xmlNode) {
	name := node.XMLName.Local
	value := cleanValue(node.Text)
	if name != "" && value != "" {
		if _, exists := out[name]; !exists {
			out[name] = value
		}
	}
	for _, child := range node.Children {
		flattenXMLNode(out, child)
	}
}

func firstValue(data map[string]string, names ...string) string {
	for _, name := range names {
		if value := cleanValue(data[name]); value != "" {
			return value
		}
	}
	return ""
}

func cleanValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if value == "-" {
		return ""
	}
	return value
}

func joinDetails(data map[string]string, names ...string) string {
	var parts []string
	for _, name := range names {
		if value := cleanValue(data[name]); value != "" {
			parts = append(parts, name+"="+compactEventText(value, eventDetailPartLimit))
		}
	}
	return strings.Join(parts, "; ")
}

func detailsFromMap(data map[string]string, max int) string {
	var keys []string
	for key, value := range data {
		if cleanValue(value) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if max <= 0 || max > len(keys) {
		max = len(keys)
	}
	parts := make([]string, 0, max)
	for _, key := range keys[:max] {
		parts = append(parts, key+"="+compactEventText(data[key], eventDetailPartLimit))
	}
	return strings.Join(parts, "; ")
}

func compactEventText(value string, max int) string {
	value = strings.Join(strings.Fields(cleanValue(value)), " ")
	runes := []rune(value)
	if max <= 0 || len(runes) <= max {
		return value
	}
	head := max * 2 / 3
	tail := max - head - 5
	if tail < 0 {
		tail = 0
	}
	return string(runes[:head]) + " ... " + string(runes[len(runes)-tail:])
}

func formatEventTime(value string) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return strings.TrimSpace(value)
	}
	return parsed.Local().Format("2006-01-02 15:04:05")
}

func logonTypeName(value string) string {
	switch strings.TrimSpace(value) {
	case "2":
		return "交互式登录"
	case "3":
		return "网络登录"
	case "4":
		return "批处理登录"
	case "5":
		return "服务登录"
	case "7":
		return "解锁"
	case "8":
		return "网络明文登录"
	case "9":
		return "新凭据登录"
	case "10":
		return "远程交互式登录/RDP"
	case "11":
		return "缓存交互式登录"
	case "":
		return ""
	default:
		return "LogonType " + value
	}
}

func securityAction(eventID, logonType string) string {
	switch eventID {
	case "4624":
		if logonType == "10" {
			return "RDP 登录成功"
		}
		return "登录成功"
	case "4625":
		if logonType == "10" {
			return "RDP 登录失败"
		}
		return "登录失败"
	case "4634":
		return "注销"
	case "4647":
		return "用户主动注销"
	case "4672":
		return "特权登录"
	case "4720":
		return "用户创建"
	case "4722":
		return "用户启用"
	case "4723":
		return "尝试修改密码"
	case "4724":
		return "密码重置"
	case "4725":
		return "用户禁用"
	case "4726":
		return "用户删除"
	case "4728":
		return "添加到全局组"
	case "4729":
		return "从全局组移除"
	case "4732":
		return "添加到本地组"
	case "4733":
		return "从本地组移除"
	case "4738":
		return "用户属性变更"
	case "4756":
		return "添加到通用组"
	case "4757":
		return "从通用组移除"
	case "4778":
		return "RDP 会话重新连接"
	case "4779":
		return "RDP 会话断开"
	case "4800":
		return "工作站锁定"
	case "4801":
		return "工作站解锁"
	default:
		return "安全事件 " + eventID
	}
}

func securityCategory(eventID, logonType string) string {
	switch eventID {
	case "4624":
		if logonType == "10" {
			return "RDP登录"
		}
		return "登录"
	case "4625":
		if logonType == "10" {
			return "RDP登录"
		}
		return "登录失败"
	case "4634", "4647":
		return "注销"
	case "4672":
		return "特权登录"
	case "4778", "4779":
		return "RDP连接"
	case "4800":
		return "工作站锁定"
	case "4801":
		return "工作站解锁"
	default:
		return "用户账户"
	}
}

func rdpAction(eventID string) string {
	switch eventID {
	case "21":
		return "RDP 会话登录"
	case "22":
		return "RDP Shell 启动"
	case "23":
		return "RDP 会话注销"
	case "24":
		return "RDP 会话断开"
	case "25":
		return "RDP 会话重新连接"
	case "39":
		return "RDP 会话断开"
	case "40":
		return "RDP 会话状态变更"
	case "1149":
		return "RDP 认证成功"
	default:
		return "RDP 事件 " + eventID
	}
}

func powershellAction(eventID string) string {
	switch eventID {
	case "400":
		return "PowerShell 引擎启动"
	case "403":
		return "PowerShell 引擎停止"
	case "600":
		return "PowerShell Provider 加载"
	case "800":
		return "PowerShell 管道执行"
	case "4103":
		return "PowerShell 模块日志"
	case "4104":
		return "PowerShell 脚本块日志"
	case "4105":
		return "PowerShell 脚本块开始"
	case "4106":
		return "PowerShell 脚本块结束"
	default:
		return "PowerShell 事件 " + eventID
	}
}

func levelName(value string) string {
	switch strings.TrimSpace(value) {
	case "1":
		return "严重"
	case "2":
		return "错误"
	case "3":
		return "警告"
	case "4":
		return "信息"
	default:
		return cleanValue(value)
	}
}

func detectSQLServerInstalled() (bool, error) {
	cmd := winexec.Command("wmic.exe", "service", "get", "Name,DisplayName", "/format:csv")
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	text := strings.ToLower(decodeCommandOutput(out))
	return strings.Contains(text, "mssql") || strings.Contains(text, "sql server") || strings.Contains(text, "sqlserveragent"), nil
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

func psDateLiteral(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format("2006-01-02 15:04:05")
}

func localizeErrors(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		lower := strings.ToLower(item)
		msg := item
		switch {
		case strings.Contains(lower, "requested registry access is not allowed") || strings.Contains(lower, "unauthorized operation") || strings.Contains(lower, "access is denied") || strings.Contains(lower, "required privilege") || strings.Contains(item, "未经授权") || strings.Contains(item, "拒绝访问") || strings.Contains(item, "权限"):
			prefix := strings.SplitN(item, ":", 2)[0]
			msg = prefix + ": 当前权限不足，无法读取对应事件日志。请用管理员权限运行本工具。"
		case strings.Contains(lower, "no events were found") || strings.Contains(item, "找不到任何与指定的选择条件匹配的事件"):
			prefix := strings.SplitN(item, ":", 2)[0]
			msg = prefix + ": 未找到匹配事件，可能日志已轮转、审计策略未启用，或该功能近期没有产生日志。"
		case strings.Contains(lower, "there is not an event log") || strings.Contains(item, "没有与"):
			prefix := strings.SplitN(item, ":", 2)[0]
			msg = prefix + ": 未发现对应事件日志，可能系统组件未安装或该日志未启用。"
		}
		if !seen[msg] {
			out = append(out, msg)
			seen[msg] = true
		}
	}
	return out
}
