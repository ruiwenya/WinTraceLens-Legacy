//go:build windows

package filetrace

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/winexec"
)

func Collect(opts Options) (Snapshot, error) {
	maxRecords := opts.MaxRecords
	if maxRecords <= 0 {
		maxRecords = 500
	}
	if maxRecords > 5000 {
		maxRecords = 5000
	}
	hours := opts.Hours
	if hours <= 0 {
		hours = 72
	}
	if hours > 24*30 {
		hours = 24 * 30
	}

	modifiedRootsText := strings.Join(cleanModifiedRoots(opts.ModifiedRoots), "\n")
	modifiedRootsB64 := base64.StdEncoding.EncodeToString([]byte(modifiedRootsText))

	script := fmt.Sprintf(`
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$max = %d
$hours = %d
$customRootsText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
$since = (Get-Date).AddHours(-1 * $hours)
$records = @()
$errors = @()
$seen = @{}

function Is-Blank($value) {
  if ($null -eq $value) { return $true }
  return ([string]$value).Trim().Length -eq 0
}

function Clean-Value($value) {
  if (Is-Blank $value) { return '' }
  return [string]$value
}

function Add-Error($source, $message) {
  $text = (Clean-Value $source) + ': ' + (Clean-Value $message)
  if (-not (Is-Blank $text)) { $script:errors += $text }
}

function Encode-Field($value) {
  $text = Clean-Value $value
  return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text))
}

function New-Record($category, $source, $name, $path, $dir, $ext, $size, $created, $modified, $accessed, $lastRun, $runCount, $suspicion, $reason, $details) {
  $sortTime = Clean-Value $lastRun
  if (Is-Blank $sortTime) { $sortTime = Clean-Value $modified }
  if (Is-Blank $sortTime) { $sortTime = Clean-Value $created }
  $obj = New-Object PSObject
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Category -Value (Clean-Value $category)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Source -Value (Clean-Value $source)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Name -Value (Clean-Value $name)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Path -Value (Clean-Value $path)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Directory -Value (Clean-Value $dir)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Extension -Value (Clean-Value $ext)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Size -Value ([int64]$size)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Created -Value (Clean-Value $created)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Modified -Value (Clean-Value $modified)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Accessed -Value (Clean-Value $accessed)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name LastRun -Value (Clean-Value $lastRun)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name RunCount -Value (Clean-Value $runCount)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Suspicion -Value (Clean-Value $suspicion)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Reason -Value (Clean-Value $reason)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name Details -Value (Clean-Value $details)
  Add-Member -InputObject $obj -MemberType NoteProperty -Name SortTime -Value (Clean-Value $sortTime)
  return $obj
}

function Add-Record($category, $source, $file, $path, $lastRun, $runCount, $suspicion, $reason, $details) {
  $actualPath = Clean-Value $path
  if ($null -ne $file) {
    try {
      if (Is-Blank $actualPath) { $actualPath = $file.FullName }
      $name = $file.Name
      $dir = $file.DirectoryName
      $ext = $file.Extension
      $size = [int64]$file.Length
      $created = if ($file.CreationTime) { $file.CreationTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
      $modified = if ($file.LastWriteTime) { $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
      $accessed = if ($file.LastAccessTime) { $file.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
    } catch {
      $name = Split-Path -Leaf $actualPath
      $dir = Split-Path -Parent $actualPath
      $ext = [IO.Path]::GetExtension($actualPath)
      $size = 0
      $created = ''
      $modified = ''
      $accessed = ''
    }
  } else {
    $name = Split-Path -Leaf $actualPath
    $dir = Split-Path -Parent $actualPath
    $ext = [IO.Path]::GetExtension($actualPath)
    $size = 0
    $created = ''
    $modified = ''
    $accessed = ''
  }
  $key = ([string]$category + '|' + [string]$source + '|' + [string]$actualPath + '|' + [string]$lastRun)
  if ($script:seen.ContainsKey($key)) { return }
  $script:seen[$key] = $true
  $script:records += New-Record $category $source $name $actualPath $dir $ext $size $created $modified $accessed $lastRun $runCount $suspicion $reason $details
}

function Suspicion-ForFile($file, $source) {
  $reasons = @()
  $level = ''
  $name = [string]$file.Name
  $base = [IO.Path]::GetFileNameWithoutExtension($name)
  $ext = ([string]$file.Extension).ToLowerInvariant()
  $execExts = @('.exe','.dll','.scr','.com','.bat','.cmd','.ps1','.vbs','.js','.jse','.wsf','.hta','.msi','.jar','.lnk')
  if ($execExts -contains $ext) {
    $reasons += '可执行/脚本扩展'
    if ($source -match 'Temp') { $level = '高' } elseif ($level -eq '') { $level = '中' }
  }
  if ($base -match '^[a-fA-F0-9]{8,}$') {
    $reasons += '疑似随机十六进制文件名'
    if ($level -eq '') { $level = '中' }
  } elseif ($base -match '^[A-Za-z0-9]{12,}$') {
    $reasons += '疑似随机字母数字文件名'
    if ($level -eq '') { $level = '中' }
  }
  if ($name -match '[\x00-\x1f\ufffd]') {
    $reasons += '文件名包含不可见或替换字符'
    $level = '高'
  }
  if ($base.Length -ge 16) {
    $digits = ([regex]::Matches($base, '\d')).Count
    if ($digits -ge [Math]::Ceiling($base.Length * 0.45)) {
      $reasons += '文件名数字占比较高'
      if ($level -eq '') { $level = '中' }
    }
  }
  if ($file.Length -gt 0 -and $file.Length -lt 4096 -and ($execExts -contains $ext)) {
    $reasons += '小体积可执行/脚本文件'
    if ($level -eq '') { $level = '中' }
  }
  if ($reasons.Count -eq 0) { return @('', '') }
  return @($level, ($reasons -join '；'))
}

function Add-FileList($category, $source, $root, $recursive, $extensionOnly, $limit) {
  if ((Is-Blank $root) -or -not (Test-Path -LiteralPath $root)) { return }
  try {
    $items = Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue
    if ($recursive) {
      $items = Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue
    }
    $execExts = @('.exe','.dll','.scr','.com','.bat','.cmd','.ps1','.vbs','.js','.jse','.wsf','.hta','.msi','.jar','.lnk')
    $items = @($items | Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $since })
    if ($extensionOnly) {
      $items = @($items | Where-Object { $execExts -contains ([string]$_.Extension).ToLowerInvariant() })
    }
    foreach ($file in @($items | Sort-Object LastWriteTime -Descending | Select-Object -First $limit)) {
      $risk = Suspicion-ForFile $file $source
      Add-Record $category $source $file $file.FullName '' '' $risk[0] $risk[1] ''
    }
  } catch {
    Add-Error $source $_.Exception.Message
  }
}

$customRoots = @()
try {
	foreach ($root in @($customRootsText -split '\r?\n')) {
    $rootText = Clean-Value $root
    if (-not (Is-Blank $rootText) -and (Test-Path -LiteralPath $rootText)) {
      $customRoots += $rootText
    }
  }
  $customRoots = @($customRoots | Select-Object -Unique)
} catch {
  Add-Error '自定义最近修改目录' $_.Exception.Message
}

$tempRoots = @()
foreach ($path in @($env:TEMP, $env:TMP, (Join-Path $env:SystemRoot 'Temp'))) {
  if (-not (Is-Blank $path)) { $tempRoots += [string]$path }
}
try {
  Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
    $candidate = Join-Path $_.FullName 'AppData\Local\Temp'
    if (Test-Path -LiteralPath $candidate) { $tempRoots += [string]$candidate }
  }
} catch {
  Add-Error 'Temp 目录枚举' $_.Exception.Message
}

$tempRoots = @($tempRoots | Select-Object -Unique)
$perRoot = [Math]::Max(30, [int]($max / 8))
foreach ($root in @($tempRoots)) {
  Add-FileList 'Temp 临时文件' 'Temp 目录' $root $true $false $perRoot
}

$scanRoots = @()
$modifiedSource = '常见落地点'
if ($customRoots.Count -gt 0) {
  $modifiedSource = '自定义目录'
  $scanRoots = @($customRoots)
} else {
  foreach ($path in @(
    (Join-Path $env:USERPROFILE 'Downloads'),
    (Join-Path $env:USERPROFILE 'Desktop'),
    (Join-Path $env:ProgramData ''),
    (Join-Path $env:PUBLIC 'Downloads'),
    (Join-Path $env:PUBLIC 'Desktop')
  )) {
    if (-not (Is-Blank $path) -and (Test-Path -LiteralPath $path)) { $scanRoots += [string]$path }
  }
  try {
    Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
      foreach ($leaf in @('Downloads','Desktop','AppData\Roaming','AppData\Local')) {
        $candidate = Join-Path $_.FullName $leaf
        if (Test-Path -LiteralPath $candidate) { $scanRoots += [string]$candidate }
      }
    }
  } catch {
    Add-Error '最近修改目录枚举' $_.Exception.Message
  }
}

$scanRoots = @($scanRoots | Select-Object -Unique)
if ($scanRoots.Count -gt 0) {
  $perRoot = [Math]::Max(30, [int]($max / [Math]::Max(1, $scanRoots.Count)))
}
foreach ($root in @($scanRoots)) {
  Add-FileList '最近修改文件' $modifiedSource $root $true $true $perRoot
}

try {
  $pfRoot = Join-Path $env:SystemRoot 'Prefetch'
  if (Test-Path -LiteralPath $pfRoot) {
    Get-ChildItem -LiteralPath $pfRoot -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Extension -ieq '.pf' -and $_.LastWriteTime -ge $since } | Sort-Object LastWriteTime -Descending | Select-Object -First $max | ForEach-Object {
      $base = [IO.Path]::GetFileNameWithoutExtension($_.Name)
      $exe = ($base -replace '-[A-Fa-f0-9]{8}$','')
      Add-Record '最近运行文件' 'Prefetch' $_ $_.FullName $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') '' '' '' ('可执行名=' + $exe)
    }
  } else {
    Add-Error 'Prefetch' ('not found: ' + $pfRoot)
  }
} catch {
  Add-Error 'Prefetch' $_.Exception.Message
}

try {
  $shell = New-Object -ComObject WScript.Shell
  $recentRoots = @()
  Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object {
    $candidate = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
    if (Test-Path -LiteralPath $candidate) { $recentRoots += $candidate }
  }
  foreach ($root in @($recentRoots | Select-Object -Unique)) {
    Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Extension -ieq '.lnk' -and $_.LastWriteTime -ge $since } | Sort-Object LastWriteTime -Descending | Select-Object -First $perRoot | ForEach-Object {
      $target = ''
      try {
        $shortcut = $shell.CreateShortcut($_.FullName)
        $target = [string]$shortcut.TargetPath
      } catch {}
      Add-Record '最近运行文件' 'Recent 快捷方式' $_ $target $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') '' '' '' ('lnk=' + $_.FullName)
    }
  }
} catch {
  Add-Error 'Recent 快捷方式' $_.Exception.Message
}

function Emit-Record($item) {
  $fields = @(
    $item.Category, $item.Source, $item.Name, $item.Path, $item.Directory, $item.Extension, $item.Size,
    $item.Created, $item.Modified, $item.Accessed, $item.LastRun, $item.RunCount,
    $item.Suspicion, $item.Reason, $item.Details
  )
  [Console]::Out.WriteLine('R|' + (($fields | ForEach-Object { Encode-Field $_ }) -join '|'))
}

foreach ($item in @($records | Sort-Object SortTime -Descending | Select-Object -First $max)) {
  Emit-Record $item
}
foreach ($err in @($errors | Select-Object -Unique)) {
  [Console]::Out.WriteLine('E|' + (Encode-Field $err))
}
[Console]::Out.WriteLine('G|' + (Encode-Field (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
`, maxRecords, hours, modifiedRootsB64)

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

	return parseLineSnapshot(out)
}

func parseLineSnapshot(out []byte) (Snapshot, error) {
	data := bytes.TrimPrefix(bytes.TrimSpace(out), []byte{0xEF, 0xBB, 0xBF})
	if len(data) == 0 {
		return Snapshot{}, errors.New("empty file trace output")
	}

	snapshot := Snapshot{GeneratedAt: time.Now().Format("2006-01-02 15:04:05")}
	lines := logicalOutputLines(strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		switch parts[0] {
		case "R":
			if len(parts) != 16 {
				snapshot.CollectionErrors = append(snapshot.CollectionErrors, "文件痕迹行字段数量异常，已忽略一条不完整输出")
				continue
			}
			fields, err := decodeFields(parts[1:])
			if err != nil {
				snapshot.CollectionErrors = append(snapshot.CollectionErrors, "文件痕迹行解析失败: "+err.Error())
				continue
			}
			size, _ := strconv.ParseInt(fields[6], 10, 64)
			snapshot.Records = append(snapshot.Records, Record{
				Category:  fields[0],
				Source:    fields[1],
				Name:      fields[2],
				Path:      fields[3],
				Directory: fields[4],
				Extension: fields[5],
				Size:      size,
				Created:   fields[7],
				Modified:  fields[8],
				Accessed:  fields[9],
				LastRun:   fields[10],
				RunCount:  fields[11],
				Suspicion: fields[12],
				Reason:    fields[13],
				Details:   fields[14],
			})
		case "E":
			if len(parts) >= 2 {
				value, err := decodeField(parts[1])
				if err == nil && strings.TrimSpace(value) != "" {
					snapshot.CollectionErrors = append(snapshot.CollectionErrors, value)
				}
			}
		case "G":
			if len(parts) >= 2 {
				value, err := decodeField(parts[1])
				if err == nil && strings.TrimSpace(value) != "" {
					snapshot.GeneratedAt = value
				}
			}
		default:
			snapshot.CollectionErrors = append(snapshot.CollectionErrors, "未知文件痕迹输出，已忽略一条不完整输出")
		}
	}
	snapshot.CollectionErrors = compactErrors(snapshot.CollectionErrors, 20)
	return snapshot, nil
}

func logicalOutputLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "R|") || strings.HasPrefix(line, "E|") || strings.HasPrefix(line, "G|") {
			out = append(out, line)
			continue
		}
		if len(out) > 0 {
			out[len(out)-1] += strings.TrimSpace(line)
			continue
		}
		out = append(out, line)
	}
	return out
}

func decodeFields(values []string) ([]string, error) {
	out := make([]string, len(values))
	for i, value := range values {
		decoded, err := decodeField(value)
		if err != nil {
			return nil, err
		}
		out[i] = decoded
	}
	return out, nil
}

func compactErrors(items []string, limit int) []string {
	if limit <= 0 {
		limit = 20
	}
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
		if len(out) < limit {
			out = append(out, item)
		}
	}
	if len(seen) > len(out) {
		out = append(out, fmt.Sprintf("还有 %d 类采集提示已折叠。", len(seen)-len(out)))
	}
	return out
}

func decodeField(value string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func cleanModifiedRoots(values []string) []string {
	seen := make(map[string]struct{})
	roots := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, value)
		if len(roots) >= 8 {
			break
		}
	}
	return roots
}
