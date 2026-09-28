//go:build windows

package main

import (
	"fmt"
	"strings"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

func (a *legacyApp) configureProcessDetailFields() {
	for _, edit := range []*walk.LineEdit{
		a.processInfoIdentity, a.processInfoParent, a.processInfoResources,
		a.processInfoSignature, a.processInfoCreated, a.processInfoMD5,
		a.processInfoPath, a.processInfoCommand,
	} {
		if edit == nil {
			continue
		}
		style := win.GetWindowLong(edit.Handle(), win.GWL_EXSTYLE)
		win.SetWindowLong(edit.Handle(), win.GWL_EXSTYLE, style&^win.WS_EX_CLIENTEDGE)
		win.SetWindowPos(edit.Handle(), 0, 0, 0, 0, 0,
			win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE|win.SWP_FRAMECHANGED)
	}
	for _, edit := range a.processInfoNarrow {
		if edit == nil {
			continue
		}
		style := win.GetWindowLong(edit.Handle(), win.GWL_EXSTYLE)
		win.SetWindowLong(edit.Handle(), win.GWL_EXSTYLE, style&^win.WS_EX_CLIENTEDGE)
		win.SetWindowPos(edit.Handle(), 0, 0, 0, 0, 0,
			win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE|win.SWP_FRAMECHANGED)
	}
}

type detailPreference uint8

const (
	detailAutomatic detailPreference = iota
	detailUserOpen
	detailUserClosed
)

func (a *legacyApp) updateDetailContentVisibility() {
	if a.processDetailPane == nil {
		return
	}
	selected := a.hasSelection
	if a.processDetailEmpty != nil {
		a.processDetailEmpty.SetVisible(!selected)
	}
	if a.processDetailHeader != nil {
		a.processDetailHeader.SetVisible(selected)
	}
	if a.processDetailTabs != nil {
		a.processDetailTabs.SetVisible(selected)
	}
	if selected {
		_ = a.processDetailPane.SetMinMaxSize(walk.Size{Height: 180}, walk.Size{Height: 360})
	} else {
		_ = a.processDetailPane.SetMinMaxSize(walk.Size{Height: 38}, walk.Size{Height: 38})
	}
	if a.processSplitter != nil {
		a.processSplitter.RequestLayout()
	}
}

func (a *legacyApp) showAbout() {
	density := "标准"
	if a.compactTables {
		density = "紧凑"
	}
	a.showCopyableTextDialog("关于 WinTraceLens Legacy", strings.Join([]string{
		"WinTraceLens Legacy",
		"版本: " + version,
		"运行时兼容目标: Go 1.20 / Windows 7 / Server 2008 R2 / Server 2012",
		"表格密度: " + density,
		"窗口边框: " + a.windowFrameMode,
		"",
		"本程序为离线现场排查与证据收集工具，不会自动上传或处置样本。",
		"",
		"使用提示",
		"- 顶部导航支持鼠标、左右方向键、Home/End 和 Enter/Space。",
		"- 紧凑显示只切换表格密度，不会重新采集或清空数据。",
		"- 搜索框支持普通关键字和 /正则/i，筛选会检查隐藏字段。",
		"- 点击表头可排序；完整字段可从查看详情、右键菜单、CSV 或取证包获取。",
		"- 建议以管理员权限运行；权限不足、日志未启用和来源不可用会显示为采集提示。",
		"- 短连接监测从程序启动后每秒采样一次，仅保留到本次退出，不能替代 WFP、ETW、Sysmon 或抓包工具。",
		"- 签名有效不等于安全，未签名也不直接代表恶意，应结合路径、行为和其他证据判断。",
	}, "\r\n"))
}

func (a *legacyApp) configureNavigationBars() {
	for _, navigation := range []*navigationBar{
		a.mainNav,
		a.processDetailNav,
		a.hostNav,
		a.findingNav,
		a.eventNav,
		a.historyNav,
	} {
		if navigation != nil {
			navigation.configure()
		}
	}
}

func (a *legacyApp) setTableDensity(compact bool) {
	a.compactTables = compact
	pointSize := 10
	headerHeight := 29
	rowHeight := 26
	label := "标准"
	toggleText := "紧凑显示"
	if compact {
		pointSize = 9
		headerHeight = 27
		rowHeight = 22
		label = "紧凑"
		toggleText = "标准显示"
	}
	if a.densityToggle != nil {
		_ = a.densityToggle.SetText(toggleText)
	}
	font, err := walk.NewFont("Microsoft YaHei UI", pointSize, 0)
	if err != nil {
		a.setStatus("表格密度切换失败：" + err.Error())
		return
	}
	for _, table := range a.allTables() {
		if table == nil {
			continue
		}
		table.SetFont(font)
		table.SetCustomHeights(headerHeight, rowHeight)
	}
	for _, navigation := range []*navigationBar{a.mainNav, a.processDetailNav, a.hostNav, a.findingNav, a.eventNav, a.historyNav} {
		if navigation != nil && navigation.widget != nil {
			navigation.widget.SetFont(font)
			navigation.revealFocus = true
			_ = navigation.widget.Invalidate()
		}
	}
	a.repaintAllTables()
	a.onMainWindowBoundsChanged()
	a.setStatus("已切换为" + label + "密度，现有数据保持不变。")
}

func (a *legacyApp) allTables() []*walk.TableView {
	return []*walk.TableView{
		a.processView, a.moduleView, a.connView, a.hostView,
		a.findingView, a.memoryView, a.driverView, a.eventView,
		a.historyConnectionView, a.historyDNSView, a.historyLiveView,
		a.historyMonitorView, a.historyAllView,
		a.fileTraceView, a.registryView,
	}
}

func (a *legacyApp) setProgressVisible(visible bool) {
	if a.progressBar == nil {
		return
	}
	a.progressBar.SetVisible(visible)
	if a.progressHost != nil {
		a.progressHost.RequestLayout()
	}
}

func (a *legacyApp) toggleProcessDetailPanel() {
	if a.processDetailPane == nil {
		return
	}
	if a.processDetailPane.Visible() {
		a.detailPreference = detailUserClosed
		a.setProcessDetailExpanded(false)
	} else {
		a.detailPreference = detailUserOpen
		a.setProcessDetailExpanded(true)
	}
}

func (a *legacyApp) onMainWindowBoundsChanged() {
	if !a.uiReady || a.mw == nil || a.processDetailPane == nil || a.detailLayoutPending {
		return
	}
	a.detailLayoutPending = true
	a.mw.Synchronize(func() {
		defer func() { a.detailLayoutPending = false }()
		a.reconcileProcessDetailLayout()
		a.updateProcessBasicLayout()
	})
}

func (a *legacyApp) updateProcessBasicLayout() {
	if a.processBasicWide == nil || a.processBasicNarrow == nil || a.mw == nil {
		return
	}
	narrow := a.mw.ClientBoundsPixels().Width < a.mw.IntFrom96DPI(860)
	if a.processNarrowMode == narrow {
		return
	}
	a.processNarrowMode = narrow
	a.processBasicWide.SetVisible(!narrow)
	a.processBasicNarrow.SetVisible(narrow)
}

func (a *legacyApp) reconcileProcessDetailLayout() {
	if a.processSplitter == nil || a.processView == nil || a.processDetailPane == nil {
		return
	}
	available := a.processSplitter.ClientBoundsPixels().Height
	headerHeight, rowHeight := a.processView.CustomHeights()
	if headerHeight <= 0 || rowHeight <= 0 || available <= 0 {
		return
	}
	a.setProcessDetailExpanded(desiredDetailExpanded(a.detailPreference, a.hasSelection, available,
		a.processSplitter.IntFrom96DPI(184),
		a.processView.IntFrom96DPI(headerHeight),
		a.processView.IntFrom96DPI(rowHeight),
		a.processSplitter.IntFrom96DPI(4), 8))
}

func desiredDetailExpanded(preference detailPreference, hasSelection bool, available, detail, header, row, handle, minimumRows int) bool {
	switch preference {
	case detailUserClosed:
		return false
	case detailUserOpen:
		return true
	default:
		return hasSelection && automaticDetailFits(available, detail, header, row, handle, minimumRows)
	}
}

func automaticDetailFits(available, detail, header, row, handle, minimumRows int) bool {
	return row > 0 && available-handle-detail-header >= minimumRows*row
}

func (a *legacyApp) setProcessDetailExpanded(expanded bool) {
	if a.processDetailPane == nil {
		return
	}
	if a.processDetailPane.Visible() == expanded {
		return
	}
	a.processDetailPane.SetVisible(expanded)
	if a.processDetailToggle != nil {
		text := "展开详情"
		if expanded {
			text = "收起详情"
		}
		_ = a.processDetailToggle.SetText(text)
	}
	if a.processSplitter != nil {
		a.processSplitter.RequestLayout()
	}
	a.repaintTable(a.processView)
}

func (a *legacyApp) updateProcessBasicInfo(pid uint32) {
	for _, item := range a.processItems {
		if item.PID != pid {
			continue
		}
		setProcessInfoField(a.processInfoIdentity, a.processInfoNarrow[0], fmt.Sprintf("%s (PID %d)", item.Name, item.PID))
		setProcessInfoField(a.processInfoParent, a.processInfoNarrow[1], fmt.Sprintf("%s (PID %d)", item.ParentName, item.ParentPID))
		setProcessInfoField(a.processInfoResources, a.processInfoNarrow[2], fmt.Sprintf("CPU %s%% | 内存 %.1f MB | 线程 %d | 句柄 %d | 连接 %d", item.CPUPercent, float64(item.WorkingSetKB)/1024, item.ThreadCount, item.HandleCount, item.ConnectionCount))
		setProcessInfoField(a.processInfoSignature, a.processInfoNarrow[3], strings.TrimSpace(item.Signature+" "+item.SignatureMsg))
		setProcessInfoField(a.processInfoCreated, a.processInfoNarrow[4], item.CreatedAt)
		md5Value := item.MD5
		if strings.TrimSpace(item.HashError) != "" {
			if strings.TrimSpace(md5Value) == "" {
				md5Value = "不可用：" + item.HashError
			} else {
				md5Value += " | 提示：" + item.HashError
			}
		}
		pathValue := item.Path
		if strings.TrimSpace(item.PathError) != "" {
			if strings.TrimSpace(pathValue) == "" {
				pathValue = "不可用：" + item.PathError
			} else {
				pathValue += " | 提示：" + item.PathError
			}
		}
		setProcessInfoField(a.processInfoMD5, a.processInfoNarrow[5], md5Value)
		setProcessInfoField(a.processInfoPath, a.processInfoNarrow[6], pathValue)
		setProcessInfoField(a.processInfoCommand, a.processInfoNarrow[7], item.CommandLine)
		return
	}
	a.clearProcessBasicInfo(fmt.Sprintf("PID %d 的基本信息已不在当前进程快照中。", pid))
}

func (a *legacyApp) clearProcessBasicInfo(message string) {
	for _, edit := range []*walk.LineEdit{
		a.processInfoIdentity,
		a.processInfoParent,
		a.processInfoResources,
		a.processInfoSignature,
		a.processInfoCreated,
		a.processInfoMD5,
		a.processInfoPath,
		a.processInfoCommand,
	} {
		setLineValue(edit, "")
	}
	for _, edit := range a.processInfoNarrow {
		setLineValue(edit, "")
	}
	setProcessInfoField(a.processInfoIdentity, a.processInfoNarrow[0], message)
}

func setProcessInfoField(wide, narrow *walk.LineEdit, value string) {
	setLineValue(wide, value)
	setLineValue(narrow, value)
}

func setLineValue(edit *walk.LineEdit, value string) {
	if edit != nil {
		_ = edit.SetText(strings.TrimSpace(value))
	}
}
