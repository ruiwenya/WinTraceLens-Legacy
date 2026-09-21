//go:build windows

package main

import (
	"fmt"
	"strings"

	"github.com/lxn/walk"
)

func (a *legacyApp) showUIHelp() {
	a.showCopyableTextDialog("WinTraceLens Legacy 帮助", strings.Join([]string{
		"界面说明",
		"- 当前版本: " + version + "；窗口边框: " + a.windowFrameMode + "。",
		"- 顶部横向导航可用鼠标、左右方向键、Home/End 和 Enter/Space 切换。",
		"- 顶部显示模式按钮可在标准和紧凑密度之间切换，不会重新采集或清空数据。",
		"- 搜索框支持普通关键字和 /正则/i，筛选仍会检查隐藏字段。",
		"- 点击表头可排序；完整字段可通过查看详情、右键菜单、CSV 或取证包保留。",
		"- 进程页可收起底部详情，为主列表释放空间；再次展开不会重新采集。",
		"",
		"权限与证据",
		"- 建议以管理员权限运行；权限不足、日志未启用和来源不可用会显示为采集提示。",
		"- 历史通信分为日志证据、DNS、当前快照和短连接监测；短连接监测从程序启动后每秒采样一次并仅保留到本次退出。",
		"- 一秒级监测可保留间歇 SYN-SENT 线索，但不能替代 WFP、ETW、Sysmon 或抓包工具。",
		"- 签名有效不等于安全，未签名也不直接代表恶意，应结合路径、行为和其他证据判断。",
	}, "\r\n"))
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
	}, "\r\n"))
}

func (a *legacyApp) showSystemFrameHelp() {
	a.showCopyableTextDialog("窗口边框说明", strings.Join([]string{
		"当前模式: " + a.windowFrameMode,
		"",
		"程序默认在系统支持时让原生标题栏颜色与应用工具栏融合，同时保留拖动、缩放、贴靠、双击最大化和 Alt+Space。",
		"如旧系统、远程桌面或高对比度环境显示异常，可使用参数 -system-frame 启动，强制保留未经调整的系统边框。",
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
	a.repaintAllTables()
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
	a.setProcessDetailExpanded(!a.processDetailPane.Visible())
}

func (a *legacyApp) onMainWindowBoundsChanged() {
	if !a.uiReady || a.mw == nil || a.processDetailPane == nil || !a.processDetailPane.Visible() {
		return
	}
	if a.mw.Bounds().Height <= 540 {
		a.setProcessDetailExpanded(false)
	}
}

func (a *legacyApp) setProcessDetailExpanded(expanded bool) {
	if a.processDetailPane == nil {
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
	if expanded {
		a.setStatus("已展开进程详情。")
	} else {
		a.setStatus("已收起进程详情，当前详情数据仍保留。")
	}
}

func (a *legacyApp) updateProcessBasicInfo(pid uint32) {
	for _, item := range a.processItems {
		if item.PID != pid {
			continue
		}
		setLineValue(a.processInfoIdentity, fmt.Sprintf("%s (PID %d)", item.Name, item.PID))
		setLineValue(a.processInfoParent, fmt.Sprintf("%s (PID %d)", item.ParentName, item.ParentPID))
		setLineValue(a.processInfoResources, fmt.Sprintf("CPU %s%% | 内存 %.1f MB | 线程 %d | 句柄 %d | 连接 %d", item.CPUPercent, float64(item.WorkingSetKB)/1024, item.ThreadCount, item.HandleCount, item.ConnectionCount))
		setLineValue(a.processInfoSignature, strings.TrimSpace(item.Signature+" "+item.SignatureMsg))
		setLineValue(a.processInfoCreated, item.CreatedAt)
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
		setLineValue(a.processInfoMD5, md5Value)
		setLineValue(a.processInfoPath, pathValue)
		setLineValue(a.processInfoCommand, item.CommandLine)
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
	setLineValue(a.processInfoIdentity, message)
}

func setLineValue(edit *walk.LineEdit, value string) {
	if edit != nil {
		_ = edit.SetText(strings.TrimSpace(value))
	}
}
