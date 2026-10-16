//go:build windows

package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/lxn/walk"
	"github.com/ruiwenya/WinTraceLens/internal/commandchain"
	"github.com/ruiwenya/WinTraceLens/internal/coverage"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/host"
)

func persistenceDetail(chain *commandchain.Chain, score int, reasons []string) string {
	lines := []string{fmt.Sprintf("评分: %d", score), "风险依据: " + strings.Join(reasons, "；")}
	if chain == nil {
		return strings.Join(lines, "\r\n")
	}
	lines = append(lines, "工作目录: "+chain.WorkingDirectory, fmt.Sprintf("异步启动: %t", chain.Asynchronous))
	add := func(label string, target commandchain.Target) {
		lines = append(lines, "", label, "原始目标: "+target.Raw, "路径: "+target.Path, "类型: "+target.Kind,
			"状态: "+target.FileStatus, "MD5: "+target.MD5, "SHA-256: "+target.SHA256,
			"签名: "+target.Signature, "签名说明: "+target.SignatureMsg,
			fmt.Sprintf("大小: %d bytes", target.Size), "创建时间(UTC): "+target.Created, "修改时间(UTC): "+target.Modified,
			"检查错误: "+target.CheckError, "哈希错误: "+target.HashError)
	}
	add("入口文件（身份不传递给后续目标）", chain.Launcher)
	for i, target := range chain.Payloads {
		add(fmt.Sprintf("后续目标 %d / %s", i+1, target.Via), target)
	}
	lines = append(lines, "", "解析限制: "+strings.Join(chain.Warnings, "；"))
	return strings.Join(lines, "\r\n")
}

func detailPreview(text string) string {
	const limit = 256 * 1024
	if len(text) <= limit {
		return text
	}
	end := limit
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end] + "\r\n\r\n[界面预览达到 256 KB 上限；复制全部、保存文本和取证包保留完整原文。]"
}

func serviceRowsWithEvidence(snapshot host.Snapshot) [][]string {
	rows := serviceRows(snapshot.Services)
	for i, service := range snapshot.Services {
		for _, event := range snapshot.MatchedEvents {
			if !strings.EqualFold(event.ServiceName, service.Name) {
				continue
			}
			rows[i][11] += fmt.Sprintf("\r\n\r\n关联事件: %s / %s / RecordID %s\r\n时间(UTC): %s\r\n账户: %s\r\n安装路径: %s\r\n消息: %s\r\n%s\r\n原始 XML:\r\n%s", event.Channel, event.EventID, event.RecordID, event.TimeUTC, event.Account, event.ImagePath, event.Message, event.Details, event.XML)
		}
		for _, entry := range snapshot.TargetedFiles {
			matched := false
			for _, ref := range entry.References {
				if ref == "服务："+service.Name {
					matched = true
				}
			}
			if matched {
				rows[i][11] += fmt.Sprintf("\r\n\r\n定向补采: %s\r\n父目录: %s\r\nACL: %s\r\nADS: %s\r\n限制: %s", entry.Target.Path, entry.DirectoryStatus, entry.DirectoryACL, strings.Join(entry.Streams, "；"), strings.Join(entry.Warnings, "；"))
			}
		}
	}
	return rows
}

func (a *legacyApp) installEvidenceDetailCells() {
	for _, entry := range []struct {
		view  *walk.TableView
		model *tableModel
	}{{a.hostView, a.hostModel}, {a.findingView, a.findingModel}} {
		view, model := entry.view, entry.model
		if view == nil {
			continue
		}
		open := false
		view.CellClicked().Attach(func(row, column int) {
			if open || row < 0 || row >= len(model.rows) || column < 0 || column >= len(model.columns) || model.columns[column].Title != "详情" {
				return
			}
			text := fullRowDetail(model.Headers(), model.rows[row])
			open = true
			// Leave the list-view notification before creating a modal dialog.
			a.mw.Synchronize(func() { defer func() { open = false }(); a.showCopyableTextDialog("完整证据详情", text) })
		})
	}
}

func coverageShort(value *coverage.Summary) string {
	if value == nil {
		return ""
	}
	if value.Status == "Insufficient telemetry" {
		return "    数据源不足，不能排除历史行为"
	}
	if value.LimitReached || value.PossiblyTruncated {
		return "    达到配额或来源不完整"
	}
	return "    受限采集"
}

func completeHostDetails(rows [][]string) [][]string {
	for i := range rows {
		for len(rows[i]) < len(hostColumns) {
			rows[i] = append(rows[i], "")
		}
		rows[i][len(hostColumns)-1] = "查看详情"
	}
	return rows
}

func (a *legacyApp) updatePersistenceFileRows(snapshot host.Snapshot) {
	if !a.fileTraceStarted {
		return
	}
	var rows [][]string
	for _, row := range a.fileTraceRows {
		if valueAt(row, 1) != "持久化定向补采" {
			rows = append(rows, row)
		}
	}
	rows = append(rows, fileTraceRows(filetrace.WithPersistence(filetrace.Snapshot{}, snapshot).Records)...)
	a.fileTraceRows = rows
	a.applyFileTraceFilter()
}

func writePersistenceEvidence(zw *zip.Writer, prefix string, machine host.Snapshot, scopes map[string]*coverage.Summary) error {
	writeJSON := func(name string, value interface{}) error {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return writeZipText(zw, prefix+name, string(raw))
	}
	if err := writeJSON("host-persistence.json", machine); err != nil {
		return err
	}
	if err := writeJSON("matched-service-events.json", machine.MatchedEvents); err != nil {
		return err
	}
	var rows [][]string
	for _, event := range machine.MatchedEvents {
		rows = append(rows, []string{event.TimeUTC, event.Channel, event.EventID, event.RecordID, event.ServiceName, event.ImagePath, event.Account, event.Provider, event.Computer, event.Message, event.XML, event.Details})
	}
	if err := writeZipCSV(zw, prefix+"matched-service-events.csv", []string{"时间UTC", "通道", "事件ID", "RecordID", "服务", "安装路径", "账户", "Provider", "计算机", "消息", "原始XML", "限制"}, rows); err != nil {
		return err
	}
	if err := writeJSON("collection-coverage.json", scopes); err != nil {
		return err
	}
	var lines []string
	for _, key := range []string{"file-traces", "security-events", "network-history"} {
		lines = append(lines, key, coverage.Describe(scopes[key]), "")
	}
	return writeZipText(zw, prefix+"collection-coverage.txt", strings.Join(lines, "\r\n"))
}
