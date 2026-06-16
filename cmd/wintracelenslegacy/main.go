//go:build windows

package main

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"

	"github.com/ruiwenya/WinTraceLens/internal/aianalysis"
	"github.com/ruiwenya/WinTraceLens/internal/analysis"
	"github.com/ruiwenya/WinTraceLens/internal/filetrace"
	"github.com/ruiwenya/WinTraceLens/internal/history"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"github.com/ruiwenya/WinTraceLens/internal/process"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

var version = "1.0.0-legacy"

var navItems = []string{"进程信息", "主机信息", "关注项", "事件日志", "历史通信", "文件痕迹", "AI分析"}

var shellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")

const (
	defaultWindowX      = 40
	defaultWindowY      = 40
	defaultWindowWidth  = 1000
	defaultWindowHeight = 680
)

var processColumns = []tableColumn{
	{"PID", 68},
	{"进程", 150},
	{"CPU%", 70},
	{"内存MB", 86},
	{"线程", 66},
	{"句柄", 66},
	{"连接数", 74},
	{"MD5", 250},
	{"签名", 120},
	{"父PID", 74},
	{"父进程", 140},
	{"创建时间", 150},
	{"路径", 420},
	{"命令行", 460},
	{"错误", 260},
}

var processModuleColumns = []tableColumn{
	{"模块", 180},
	{"MD5", 250},
	{"签名", 120},
	{"基址", 120},
	{"大小KB", 80},
	{"路径", 420},
	{"错误", 240},
}

var processConnectionColumns = []tableColumn{
	{"协议", 80},
	{"远程类型", 100},
	{"本地地址", 220},
	{"远程地址", 220},
	{"状态", 120},
	{"本地端口", 90},
	{"远程端口", 90},
}

var serviceColumns = []tableColumn{
	{"服务名", 150},
	{"显示名", 220},
	{"状态", 80},
	{"启动", 90},
	{"账户", 180},
	{"MD5", 250},
	{"签名", 120},
	{"路径", 380},
	{"命令", 420},
	{"错误", 240},
}

var taskColumns = []tableColumn{
	{"任务名", 180},
	{"任务路径", 260},
	{"状态", 90},
	{"运行状态", 100},
	{"作者", 160},
	{"MD5", 250},
	{"签名", 120},
	{"可执行路径", 380},
	{"命令", 380},
	{"参数", 260},
	{"错误", 240},
}

var startupColumns = []tableColumn{
	{"来源", 130},
	{"名称", 180},
	{"MD5", 250},
	{"签名", 120},
	{"路径", 380},
	{"命令", 420},
	{"位置", 320},
	{"错误", 240},
}

var userColumns = []tableColumn{
	{"用户名", 180},
	{"SID", 320},
	{"禁用", 70},
	{"锁定", 70},
	{"需要密码", 90},
	{"本地账户", 90},
}

var ifeoColumns = []tableColumn{
	{"目标镜像", 170},
	{"Debugger MD5", 250},
	{"签名", 120},
	{"Debugger 路径", 380},
	{"Debugger", 420},
	{"注册表路径", 420},
	{"错误", 240},
}

var persistenceColumns = []tableColumn{
	{"类别", 150},
	{"名称", 220},
	{"值", 420},
	{"位置", 420},
	{"MD5", 250},
	{"签名", 120},
	{"路径", 420},
	{"错误", 240},
}

var findingColumns = []tableColumn{
	{"级别", 70},
	{"来源", 100},
	{"名称", 220},
	{"原因", 260},
	{"MD5", 250},
	{"签名", 120},
	{"路径", 420},
	{"命令", 420},
	{"补充信息", 380},
}

var eventColumns = []tableColumn{
	{"时间", 150},
	{"分类", 110},
	{"动作", 160},
	{"事件ID", 80},
	{"账户", 160},
	{"来源IP", 130},
	{"登录类型", 160},
	{"进程", 220},
	{"服务", 170},
	{"命令", 360},
	{"详情", 460},
}

var historyColumns = []tableColumn{
	{"时间", 150},
	{"来源", 150},
	{"事件ID", 80},
	{"进程", 220},
	{"PID", 80},
	{"协议", 70},
	{"本地", 220},
	{"远程", 220},
	{"DNS/查询", 240},
	{"动作", 100},
	{"用户", 160},
	{"详情", 420},
}

var fileTraceColumns = []tableColumn{
	{"分类", 120},
	{"来源", 130},
	{"文件名", 220},
	{"可疑", 70},
	{"原因", 220},
	{"修改时间", 150},
	{"最近运行", 150},
	{"运行次数", 80},
	{"大小KB", 80},
	{"扩展名", 80},
	{"路径", 460},
	{"详情", 420},
}

var hostColumns = []tableColumn{
	{"类型", 90},
	{"名称", 220},
	{"状态/属性", 220},
	{"账户/作者/SID", 320},
	{"MD5", 250},
	{"签名", 120},
	{"路径", 420},
	{"命令/详情", 420},
	{"位置/注册表", 380},
	{"错误", 240},
}

type tableColumn struct {
	Title string
	Width int
}

type tableModel struct {
	walk.TableModelBase
	walk.SorterBase
	columns []tableColumn
	rows    [][]string
}

func newTableModel(columns []tableColumn) *tableModel {
	return &tableModel{columns: columns}
}

func (m *tableModel) RowCount() int {
	return len(m.rows)
}

func (m *tableModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.rows) || col < 0 || col >= len(m.rows[row]) {
		return ""
	}
	return m.rows[row][col]
}

func (m *tableModel) Sort(col int, order walk.SortOrder) error {
	if col >= 0 && col < len(m.columns) {
		m.sortRows(col, order)
	}
	return m.SorterBase.Sort(col, order)
}

func (m *tableModel) SetRows(rows [][]string) {
	m.rows = rows
	if col := m.SortedColumn(); col >= 0 {
		m.sortRows(col, m.SortOrder())
	}
	m.PublishRowsReset()
}

func (m *tableModel) sortRows(col int, order walk.SortOrder) {
	sort.SliceStable(m.rows, func(i, j int) bool {
		a := ""
		b := ""
		if col < len(m.rows[i]) {
			a = m.rows[i][col]
		}
		if col < len(m.rows[j]) {
			b = m.rows[j][col]
		}
		less := naturalLess(a, b)
		if order == walk.SortDescending {
			return !less
		}
		return less
	})
}

func (m *tableModel) Rows() [][]string {
	out := make([][]string, len(m.rows))
	for i := range m.rows {
		out[i] = append([]string(nil), m.rows[i]...)
	}
	return out
}

func (m *tableModel) Headers() []string {
	headers := make([]string, len(m.columns))
	for i, col := range m.columns {
		headers[i] = col.Title
	}
	return headers
}

type legacyApp struct {
	mw             *walk.MainWindow
	mainTabs       *walk.TabWidget
	navList        *walk.ListBox
	status         *walk.Label
	hashLimitBytes int64
	processStarted bool
	hostStarted    bool
	findingStarted bool
	eventStarted   bool

	processSearch  *walk.LineEdit
	processModel   *tableModel
	processView    *walk.TableView
	processRows    [][]string
	processSummary *walk.Label
	processDetail  *walk.Label
	moduleModel    *tableModel
	moduleView     *walk.TableView
	moduleRows     [][]string
	connModel      *tableModel
	connView       *walk.TableView
	connRows       [][]string
	selectedPID    uint32
	selectedName   string
	hasSelection   bool
	detailSeq      int

	hostSearch          *walk.LineEdit
	hostSummary         *walk.Label
	hostModel           *tableModel
	hostView            *walk.TableView
	hostKind            string
	serviceModel        *tableModel
	serviceView         *walk.TableView
	taskModel           *tableModel
	taskView            *walk.TableView
	startupModel        *tableModel
	startupView         *walk.TableView
	userModel           *tableModel
	userView            *walk.TableView
	ifeoModel           *tableModel
	ifeoView            *walk.TableView
	persistenceModel    *tableModel
	persistenceView     *walk.TableView
	serviceRows         [][]string
	taskRows            [][]string
	startupRows         [][]string
	userRows            [][]string
	ifeoRows            [][]string
	persistenceRows     [][]string
	hostServiceRows     [][]string
	hostTaskRows        [][]string
	hostStartupRows     [][]string
	hostUserRows        [][]string
	hostIFEORows        [][]string
	hostPersistenceRows [][]string
	hostAllRows         [][]string

	findingSearch  *walk.LineEdit
	findingSummary *walk.Label
	findingModel   *tableModel
	findingView    *walk.TableView
	findingRows    [][]string

	eventSearch   *walk.LineEdit
	eventSummary  *walk.Label
	eventStart    *walk.LineEdit
	eventEnd      *walk.LineEdit
	eventMax      *walk.LineEdit
	eventModel    *tableModel
	eventView     *walk.TableView
	eventRows     [][]string
	eventWarnings [][]string
	eventCategory string

	historyStarted  bool
	historySearch   *walk.LineEdit
	historySummary  *walk.Label
	historyStart    *walk.LineEdit
	historyEnd      *walk.LineEdit
	historyMax      *walk.LineEdit
	historyModel    *tableModel
	historyView     *walk.TableView
	historyRows     [][]string
	historyWarnings [][]string

	fileTraceStarted  bool
	fileTraceSearch   *walk.LineEdit
	fileTraceSummary  *walk.Label
	fileTraceHours    *walk.LineEdit
	fileTraceMax      *walk.LineEdit
	fileTraceRoots    *walk.LineEdit
	fileTraceModel    *tableModel
	fileTraceView     *walk.TableView
	fileTraceRows     [][]string
	fileTraceWarnings [][]string

	aiProvider       *walk.ComboBox
	aiModel          *walk.ComboBox
	aiAPIKey         *walk.LineEdit
	aiBaseURL        *walk.LineEdit
	aiQuestion       *walk.TextEdit
	aiFollowUp       *walk.TextEdit
	aiOutput         *walk.TextEdit
	aiSummary        *walk.Label
	aiSecProcesses   *walk.CheckBox
	aiSecFindings    *walk.CheckBox
	aiSecHost        *walk.CheckBox
	aiSecFileTrace   *walk.CheckBox
	aiSecHistory     *walk.CheckBox
	aiSecSecurity    *walk.CheckBox
	aiChat           []aianalysis.Message
	aiLastTranscript string
	aiBusy           bool
}

func main() {
	runtime.LockOSThread()

	hashLimitMB := flag.Int64("hash-limit-mb", 512, "skip MD5 hashing for executable files larger than this size")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	app := newLegacyApp(*hashLimitMB * 1024 * 1024)
	if err := app.run(); err != nil {
		walk.MsgBox(nil, "WinTraceLens Legacy 启动失败", err.Error(), walk.MsgBoxIconError)
	}
}

func newLegacyApp(hashLimitBytes int64) *legacyApp {
	return &legacyApp{
		hashLimitBytes:   hashLimitBytes,
		processModel:     newTableModel(processColumns),
		moduleModel:      newTableModel(processModuleColumns),
		connModel:        newTableModel(processConnectionColumns),
		hostModel:        newTableModel(hostColumns),
		hostKind:         "services",
		serviceModel:     newTableModel(serviceColumns),
		taskModel:        newTableModel(taskColumns),
		startupModel:     newTableModel(startupColumns),
		userModel:        newTableModel(userColumns),
		ifeoModel:        newTableModel(ifeoColumns),
		persistenceModel: newTableModel(persistenceColumns),
		findingModel:     newTableModel(findingColumns),
		eventModel:       newTableModel(eventColumns),
		eventCategory:    "all",
		historyModel:     newTableModel(historyColumns),
		fileTraceModel:   newTableModel(fileTraceColumns),
	}
}

func (a *legacyApp) run() error {
	mainWindow := MainWindow{
		AssignTo: &a.mw,
		Title:    "WinTraceLens Legacy",
		Bounds:   defaultDeclarativeBounds(),
		MinSize:  Size{Width: 760, Height: 500},
		Font:     Font{Family: "Microsoft YaHei UI", PointSize: 9},
		Background: SolidColorBrush{
			Color: walk.RGB(240, 243, 247),
		},
		Layout: VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 8}, Spacing: 8},
		Children: []Widget{
			a.header(),
			a.contentArea(),
			Composite{
				Background: SolidColorBrush{Color: walk.RGB(235, 241, 248)},
				Layout:     HBox{Margins: Margins{Left: 10, Top: 6, Right: 10, Bottom: 6}},
				Children: []Widget{
					Label{AssignTo: &a.status, Text: "就绪。建议以管理员权限运行，以获得完整事件日志和系统信息。", TextColor: walk.RGB(50, 67, 89), StretchFactor: 1},
				},
			},
		},
	}

	if err := mainWindow.Create(); err != nil {
		return err
	}

	a.mw.Starting().Once(func() {
		a.refreshProcesses()
		a.refreshFileTrace()
	})
	returnCode := a.mw.Run()
	if returnCode != 0 {
		return fmt.Errorf("窗口已退出，返回码 %d", returnCode)
	}
	return nil
}

func (a *legacyApp) header() Widget {
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(30, 48, 71)},
		Layout:     HBox{Margins: Margins{Left: 14, Top: 10, Right: 14, Bottom: 10}, Spacing: 10},
		Children: []Widget{
			Composite{
				MinSize:    Size{Width: 5},
				Background: SolidColorBrush{Color: walk.RGB(72, 161, 221)},
			},
			Composite{
				StretchFactor: 1,
				Layout:        VBox{MarginsZero: true, Spacing: 4},
				Children: []Widget{
					Label{Text: "WinTraceLens Legacy", Font: Font{Family: "Microsoft YaHei UI", PointSize: 14, Bold: true}, TextColor: walk.RGB(255, 255, 255)},
					Label{Text: "Windows 7 / Server 2012 专用原生界面。模块首次打开会自动采集，耗时操作会在后台执行。", TextColor: walk.RGB(192, 204, 219)},
				},
			},
			PushButton{Text: "恢复窗口", MinSize: Size{Width: 92}, OnClicked: a.restoreWindow},
			PushButton{Text: "导出取证包", MinSize: Size{Width: 116}, OnClicked: a.exportEvidencePackage},
			Label{Text: version + "  Go 1.20", TextColor: walk.RGB(213, 222, 233)},
		},
	}
}

func defaultDeclarativeBounds() Rectangle {
	return Rectangle{X: defaultWindowX, Y: defaultWindowY, Width: defaultWindowWidth, Height: defaultWindowHeight}
}

func defaultWalkBounds() walk.Rectangle {
	return walk.Rectangle{X: defaultWindowX, Y: defaultWindowY, Width: defaultWindowWidth, Height: defaultWindowHeight}
}

func (a *legacyApp) restoreWindow() {
	if a.mw == nil {
		return
	}
	if a.mw.Fullscreen() {
		_ = a.mw.SetFullscreen(false)
	}
	win.ShowWindow(a.mw.Handle(), win.SW_RESTORE)
	_ = a.mw.SetBounds(defaultWalkBounds())
	a.mw.SetSuspended(false)
	a.setStatus("窗口已恢复到默认大小。")
}

func (a *legacyApp) openSystemTool(label, target string) {
	file, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		a.showError("打开"+label+"失败", err)
		return
	}
	verb, _ := syscall.UTF16PtrFromString("open")
	var hwnd uintptr
	if a.mw != nil {
		hwnd = uintptr(a.mw.Handle())
	}
	ret, _, callErr := shellExecuteW.Call(
		hwnd,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0,
		0,
		uintptr(win.SW_SHOWNORMAL),
	)
	if ret <= 32 {
		if ret == 0 && callErr != syscall.Errno(0) {
			a.showError("打开"+label+"失败", callErr)
			return
		}
		a.showError("打开"+label+"失败", fmt.Errorf("无法启动 %s，ShellExecute 返回码 %d", target, ret))
		return
	}
	a.setStatus("已请求打开系统界面：" + label)
}

func (a *legacyApp) contentArea() Widget {
	return Composite{
		StretchFactor: 1,
		Layout:        HBox{MarginsZero: true, Spacing: 8},
		Children: []Widget{
			a.sideNav(),
			TabWidget{
				AssignTo:              &a.mainTabs,
				ContentMarginsZero:    true,
				StretchFactor:         1,
				OnCurrentIndexChanged: a.onMainTabChanged,
				Pages: []TabPage{
					{Title: "进程信息", Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 8}, Children: a.modulePage(
						"进程信息",
						"查看进程路径、父进程、CPU、内存、线程、句柄、MD5、签名状态和当前网络连接数量。",
						a.summaryBar(&a.processSummary, "等待采集进程信息。"),
						a.processToolbar(),
						a.processPage(),
					)},
					{Title: "主机信息", Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 8}, Children: a.modulePage(
						"主机信息",
						"汇总服务、计划任务、启动项、本地用户和镜像劫持，适合快速检查持久化位置。",
						a.summaryBar(&a.hostSummary, "等待采集主机信息。"),
						a.hostToolbar(),
						a.hostTable(),
					)},
					{Title: "关注项", Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 8}, Children: a.modulePage(
						"关注项",
						"基于进程、签名、路径、服务和启动项生成需要优先核查的条目。",
						a.summaryBar(&a.findingSummary, "等待生成关注项。"),
						a.findingToolbar(),
						a.assignedTableWithMinHeight(findingColumns, a.findingModel, &a.findingView, nil, nil, 180),
					)},
					{Title: "事件日志", Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 8}, Children: a.modulePage(
						"事件日志",
						"默认读取最近 7 天常见安全事件，建议按时间范围缩小查询以减少旧机器压力。",
						a.summaryBar(&a.eventSummary, "等待读取事件日志。"),
						a.eventToolbar(),
						a.assignedTableWithMinHeight(eventColumns, a.eventModel, &a.eventView, nil, a.eventContextMenu(), 180),
					)},
					{Title: "历史通信", Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 8}, Children: a.modulePage(
						"历史通信",
						"汇总 Sysmon、DNS Client、WFP、防火墙日志和 DNS 缓存。DNS 缓存没有可靠时间和进程归属。",
						a.summaryBar(&a.historySummary, "等待读取历史通信。"),
						a.historyToolbar(),
						a.assignedTableWithMinHeight(historyColumns, a.historyModel, &a.historyView, nil, a.historyContextMenu(), 180),
					)},
					{Title: "文件痕迹", Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 8}, Children: a.modulePage(
						"文件痕迹",
						"查看最近修改文件、最近运行文件和 Temp 目录可疑文件。可填写 C:\\ 或指定目录缩小扫描范围。",
						a.summaryBar(&a.fileTraceSummary, "等待扫描文件痕迹。"),
						a.fileTraceToolbar(),
						a.assignedTableWithMinHeight(fileTraceColumns, a.fileTraceModel, &a.fileTraceView, nil, a.fileTraceContextMenu(), 180),
					)},
					{Title: "AI分析", Layout: VBox{Margins: Margins{Left: 8, Top: 8, Right: 8, Bottom: 8}, Spacing: 8}, Children: a.modulePage(
						"AI分析",
						"选择在线模型后，把当前采集结果发送给 AI 辅助判断异常点和下一步排查方向。API Key 仅保存在本次运行内存中。",
						a.summaryBar(&a.aiSummary, "等待配置 AI 分析。"),
						a.aiToolbar(),
						a.aiPage(),
					)},
				},
			},
		},
	}
}

func (a *legacyApp) sideNav() Widget {
	return Composite{
		MinSize:    Size{Width: 136},
		Background: SolidColorBrush{Color: walk.RGB(28, 42, 61)},
		Layout:     VBox{Margins: Margins{Left: 10, Top: 12, Right: 10, Bottom: 12}, Spacing: 10},
		Children: []Widget{
			Label{Text: "功能导航", Font: Font{Family: "Microsoft YaHei UI", PointSize: 10, Bold: true}, TextColor: walk.RGB(235, 241, 248)},
			Label{Text: "选择模块后自动采集", TextColor: walk.RGB(155, 170, 190)},
			ListBox{
				AssignTo:              &a.navList,
				Model:                 navItems,
				CurrentIndex:          0,
				StretchFactor:         1,
				Background:            SolidColorBrush{Color: walk.RGB(245, 248, 252)},
				OnCurrentIndexChanged: a.onNavChanged,
			},
		},
	}
}

func (a *legacyApp) modulePage(title, detail string, summary Widget, toolbar Widget, body Widget) []Widget {
	return []Widget{
		Composite{
			Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)},
			Layout:     VBox{Margins: Margins{Left: 12, Top: 8, Right: 12, Bottom: 8}, Spacing: 6},
			Children: []Widget{
				Label{Text: title, Font: Font{Family: "Microsoft YaHei UI", PointSize: 11, Bold: true}, TextColor: walk.RGB(28, 40, 56)},
				Label{Text: detail, TextColor: walk.RGB(86, 99, 118)},
				summary,
				toolbar,
			},
		},
		body,
	}
}

func (a *legacyApp) summaryBar(assignTo **walk.Label, text string) Widget {
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(237, 245, 252)},
		Layout:     HBox{Margins: Margins{Left: 10, Top: 4, Right: 10, Bottom: 4}},
		Children: []Widget{
			Label{AssignTo: assignTo, Text: text, TextColor: walk.RGB(40, 74, 108), StretchFactor: 1},
		},
	}
}

func (a *legacyApp) processToolbar() Widget {
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(246, 248, 251)},
		Layout:     HBox{Margins: Margins{Left: 10, Top: 7, Right: 10, Bottom: 7}, Spacing: 8},
		Children: []Widget{
			Label{Text: "关键字", TextColor: walk.RGB(50, 67, 89)},
			LineEdit{AssignTo: &a.processSearch, StretchFactor: 1, OnTextChanged: a.applyProcessFilter},
			Label{Text: "进程名 / PID / MD5 / 路径 / 签名", TextColor: walk.RGB(112, 122, 138)},
			PushButton{Text: "刷新", MinSize: Size{Width: 84}, OnClicked: a.refreshProcesses},
			PushButton{Text: "导出 CSV", MinSize: Size{Width: 96}, OnClicked: func() { a.exportModel("processes", a.processModel) }},
		},
	}
}

func (a *legacyApp) processPage() Widget {
	return VSplitter{
		StretchFactor: 1,
		HandleWidth:   5,
		Children: []Widget{
			a.assignedTableWithMinHeight(processColumns, a.processModel, &a.processView, a.onProcessSelected, a.processContextMenu(), 220),
			a.processDetailPanel(),
		},
	}
}

func (a *legacyApp) processDetailPanel() Widget {
	return ScrollView{
		HorizontalFixed: true,
		VerticalFixed:   false,
		StretchFactor:   1,
		MinSize:         Size{Height: 120},
		Background:      SolidColorBrush{Color: walk.RGB(242, 246, 251)},
		Layout:          VBox{Margins: Margins{Left: 0, Top: 0, Right: 0, Bottom: 0}, Spacing: 4},
		Children: []Widget{
			Composite{
				Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     HBox{Margins: Margins{Left: 12, Top: 6, Right: 12, Bottom: 6}, Spacing: 8},
				Children: []Widget{
					Label{Text: "进程详情", Font: Font{Family: "Microsoft YaHei UI", PointSize: 9, Bold: true}, TextColor: walk.RGB(28, 40, 56)},
					Label{AssignTo: &a.processDetail, Text: "选择进程后显示模块列表和网络连接。", TextColor: walk.RGB(70, 82, 98), StretchFactor: 1},
					PushButton{Text: "刷新详情", MinSize: Size{Width: 84}, OnClicked: a.refreshSelectedProcessDetails},
					PushButton{Text: "导出模块", MinSize: Size{Width: 84}, OnClicked: a.exportSelectedModules},
					PushButton{Text: "导出连接", MinSize: Size{Width: 84}, OnClicked: a.exportSelectedConnections},
				},
			},
			TabWidget{
				ContentMarginsZero: true,
				StretchFactor:      1,
				MinSize:            Size{Height: 100},
				Pages: []TabPage{
					{Title: "模块列表", Layout: VBox{Margins: Margins{Left: 0, Top: 4, Right: 0, Bottom: 0}}, Children: []Widget{
						a.assignedTableWithMinHeight(processModuleColumns, a.moduleModel, &a.moduleView, nil, a.moduleContextMenu(), 90),
					}},
					{Title: "网络连接", Layout: VBox{Margins: Margins{Left: 0, Top: 4, Right: 0, Bottom: 0}}, Children: []Widget{
						a.assignedTableWithMinHeight(processConnectionColumns, a.connModel, &a.connView, nil, a.connectionContextMenu(), 90),
					}},
				},
			},
		},
	}
}

func (a *legacyApp) hostToolbar() Widget {
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(246, 248, 251)},
		Layout:     VBox{Margins: Margins{Left: 10, Top: 7, Right: 10, Bottom: 7}, Spacing: 6},
		Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true, Spacing: 7}, Children: []Widget{
				PushButton{Text: "服务", MinSize: Size{Width: 72}, OnClicked: func() { a.setHostKind("services") }},
				PushButton{Text: "计划任务", MinSize: Size{Width: 84}, OnClicked: func() { a.setHostKind("tasks") }},
				PushButton{Text: "启动项", MinSize: Size{Width: 72}, OnClicked: func() { a.setHostKind("startup") }},
				PushButton{Text: "用户", MinSize: Size{Width: 62}, OnClicked: func() { a.setHostKind("users") }},
				PushButton{Text: "镜像劫持", MinSize: Size{Width: 84}, OnClicked: func() { a.setHostKind("ifeo") }},
				PushButton{Text: "持久化", MinSize: Size{Width: 78}, OnClicked: func() { a.setHostKind("persistence") }},
				Label{Text: "关键字", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.hostSearch, StretchFactor: 1, OnTextChanged: a.applyHostFilter},
				PushButton{Text: "刷新", MinSize: Size{Width: 84}, OnClicked: a.refreshHost},
				PushButton{Text: "导出当前表", MinSize: Size{Width: 110}, OnClicked: a.exportCurrentHostTable},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 7}, Children: []Widget{
				Label{Text: "打开系统界面", TextColor: walk.RGB(50, 67, 89)},
				PushButton{Text: "服务管理器", MinSize: Size{Width: 92}, OnClicked: func() { a.openSystemTool("服务管理器", "services.msc") }},
				PushButton{Text: "任务计划程序", MinSize: Size{Width: 104}, OnClicked: func() { a.openSystemTool("任务计划程序", "taskschd.msc") }},
				PushButton{Text: "系统配置启动项", MinSize: Size{Width: 118}, OnClicked: func() { a.openSystemTool("系统配置启动项", "msconfig.exe") }},
				PushButton{Text: "本地用户和组", MinSize: Size{Width: 104}, OnClicked: func() { a.openSystemTool("本地用户和组", "lusrmgr.msc") }},
				PushButton{Text: "注册表", MinSize: Size{Width: 76}, OnClicked: func() { a.openSystemTool("注册表", "regedit.exe") }},
				HSpacer{},
				Label{Text: "用于与本工具采集结果对比", TextColor: walk.RGB(112, 122, 138)},
			}},
		},
	}
}

func (a *legacyApp) hostTable() Widget {
	return a.assignedTableWithMinHeight(hostColumns, a.hostModel, &a.hostView, nil, nil, 180)
}

func (a *legacyApp) findingToolbar() Widget {
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(246, 248, 251)},
		Layout:     HBox{Margins: Margins{Left: 10, Top: 7, Right: 10, Bottom: 7}, Spacing: 8},
		Children: []Widget{
			Label{Text: "关键字", TextColor: walk.RGB(50, 67, 89)},
			LineEdit{AssignTo: &a.findingSearch, StretchFactor: 1, OnTextChanged: a.applyFindingFilter},
			Label{Text: "级别 / 来源 / 原因 / MD5 / 路径", TextColor: walk.RGB(112, 122, 138)},
			PushButton{Text: "刷新", MinSize: Size{Width: 84}, OnClicked: a.refreshFindings},
			PushButton{Text: "导出 CSV", MinSize: Size{Width: 96}, OnClicked: func() { a.exportModel("findings", a.findingModel) }},
		},
	}
}

func (a *legacyApp) eventToolbar() Widget {
	start := time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	end := time.Now().Format("2006-01-02")
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(246, 248, 251)},
		Layout:     VBox{Margins: Margins{Left: 10, Top: 7, Right: 10, Bottom: 7}, Spacing: 6},
		Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				Label{Text: "开始", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.eventStart, Text: start, MaxSize: Size{Width: 110}},
				Label{Text: "结束", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.eventEnd, Text: end, MaxSize: Size{Width: 110}},
				Label{Text: "条数", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.eventMax, Text: "500", MaxSize: Size{Width: 70}},
				Label{Text: "搜索", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.eventSearch, StretchFactor: 1, OnTextChanged: a.applyEventFilter},
				PushButton{Text: "读取日志", MinSize: Size{Width: 92}, OnClicked: a.refreshEvents},
				PushButton{Text: "导出 CSV", MinSize: Size{Width: 96}, OnClicked: func() { a.exportModel("security-events", a.eventModel) }},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 7}, Children: []Widget{
				Label{Text: "分类", TextColor: walk.RGB(50, 67, 89)},
				PushButton{Text: "全部", MinSize: Size{Width: 58}, OnClicked: func() { a.setEventCategory("all") }},
				PushButton{Text: "登录成功", MinSize: Size{Width: 78}, OnClicked: func() { a.setEventCategory("logon-success") }},
				PushButton{Text: "登录失败", MinSize: Size{Width: 78}, OnClicked: func() { a.setEventCategory("logon-failed") }},
				PushButton{Text: "RDP", MinSize: Size{Width: 58}, OnClicked: func() { a.setEventCategory("rdp") }},
				PushButton{Text: "服务创建", MinSize: Size{Width: 78}, OnClicked: func() { a.setEventCategory("service") }},
				PushButton{Text: "用户创建", MinSize: Size{Width: 78}, OnClicked: func() { a.setEventCategory("user-create") }},
				PushButton{Text: "PowerShell", MinSize: Size{Width: 92}, OnClicked: func() { a.setEventCategory("powershell") }},
			}},
		},
	}
}

func (a *legacyApp) historyToolbar() Widget {
	start := time.Now().AddDate(0, 0, -7).Format("2006-01-02")
	end := time.Now().Format("2006-01-02")
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(246, 248, 251)},
		Layout:     HBox{Margins: Margins{Left: 10, Top: 7, Right: 10, Bottom: 7}, Spacing: 8},
		Children: []Widget{
			Label{Text: "开始", TextColor: walk.RGB(50, 67, 89)},
			LineEdit{AssignTo: &a.historyStart, Text: start, MaxSize: Size{Width: 110}},
			Label{Text: "结束", TextColor: walk.RGB(50, 67, 89)},
			LineEdit{AssignTo: &a.historyEnd, Text: end, MaxSize: Size{Width: 110}},
			Label{Text: "条数", TextColor: walk.RGB(50, 67, 89)},
			LineEdit{AssignTo: &a.historyMax, Text: "500", MaxSize: Size{Width: 70}},
			Label{Text: "搜索", TextColor: walk.RGB(50, 67, 89)},
			LineEdit{AssignTo: &a.historySearch, StretchFactor: 1, OnTextChanged: a.applyHistoryFilter},
			PushButton{Text: "读取记录", MinSize: Size{Width: 92}, OnClicked: a.refreshHistory},
			PushButton{Text: "导出 CSV", MinSize: Size{Width: 96}, OnClicked: func() { a.exportModel("network-history", a.historyModel) }},
		},
	}
}

func (a *legacyApp) fileTraceToolbar() Widget {
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(246, 248, 251)},
		Layout:     VBox{Margins: Margins{Left: 10, Top: 7, Right: 10, Bottom: 7}, Spacing: 6},
		Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				Label{Text: "最近小时", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.fileTraceHours, Text: "72", MaxSize: Size{Width: 70}},
				Label{Text: "条数", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.fileTraceMax, Text: "500", MaxSize: Size{Width: 70}},
				Label{Text: "搜索", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.fileTraceSearch, StretchFactor: 1, OnTextChanged: a.applyFileTraceFilter},
				PushButton{Text: "开始扫描", MinSize: Size{Width: 92}, OnClicked: a.refreshFileTrace},
				PushButton{Text: "导出 CSV", MinSize: Size{Width: 96}, OnClicked: func() { a.exportModel("file-traces", a.fileTraceModel) }},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				Label{Text: "扫描目录", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.fileTraceRoots, StretchFactor: 1},
				Label{Text: "可选，多个目录用分号分隔；C 盘全盘可能较慢。", TextColor: walk.RGB(112, 122, 138)},
			}},
		},
	}
}

func (a *legacyApp) aiToolbar() Widget {
	return Composite{
		Background: SolidColorBrush{Color: walk.RGB(246, 248, 251)},
		Layout:     VBox{Margins: Margins{Left: 10, Top: 7, Right: 10, Bottom: 7}, Spacing: 6},
		Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				Label{Text: "厂商", TextColor: walk.RGB(50, 67, 89)},
				ComboBox{AssignTo: &a.aiProvider, Model: []string{"OpenAI", "DeepSeek", "Kimi", "Qwen", "Custom"}, CurrentIndex: 0, Editable: true, MinSize: Size{Width: 130}, MaxSize: Size{Width: 150}, OnCurrentIndexChanged: a.onAIProviderChanged},
				Label{Text: "模型", TextColor: walk.RGB(50, 67, 89)},
				ComboBox{AssignTo: &a.aiModel, Model: aiModelOptions(), CurrentIndex: 0, Editable: true, MinSize: Size{Width: 190}, MaxSize: Size{Width: 240}},
				HSpacer{},
				PushButton{Text: "开始分析", MinSize: Size{Width: 94}, OnClicked: a.startAIAnalysis},
				PushButton{Text: "复制结果", MinSize: Size{Width: 86}, OnClicked: a.copyAITranscript},
				PushButton{Text: "清空对话", MinSize: Size{Width: 86}, OnClicked: a.clearAIConversation},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				Label{Text: "API Key", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.aiAPIKey, PasswordMode: true, StretchFactor: 1},
				Label{Text: "接口地址", TextColor: walk.RGB(50, 67, 89)},
				LineEdit{AssignTo: &a.aiBaseURL, StretchFactor: 1},
			}},
		},
	}
}

func (a *legacyApp) aiPage() Widget {
	return Composite{
		StretchFactor: 1,
		Layout:        HBox{MarginsZero: true, Spacing: 10},
		Children: []Widget{
			Composite{
				MinSize:    Size{Width: 285},
				Background: SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:     VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
				Children: []Widget{
					Label{Text: "证据范围", Font: Font{Family: "Microsoft YaHei UI", PointSize: 9, Bold: true}, TextColor: walk.RGB(28, 40, 56)},
					CheckBox{AssignTo: &a.aiSecProcesses, Text: "进程信息", Checked: true},
					CheckBox{AssignTo: &a.aiSecFindings, Text: "关注项", Checked: true},
					CheckBox{AssignTo: &a.aiSecHost, Text: "主机信息", Checked: true},
					CheckBox{AssignTo: &a.aiSecFileTrace, Text: "文件痕迹", Checked: true},
					CheckBox{AssignTo: &a.aiSecHistory, Text: "历史通信", Checked: true},
					CheckBox{AssignTo: &a.aiSecSecurity, Text: "事件日志", Checked: true},
					Label{Text: "分析问题", Font: Font{Family: "Microsoft YaHei UI", PointSize: 9, Bold: true}, TextColor: walk.RGB(28, 40, 56)},
					TextEdit{
						AssignTo:      &a.aiQuestion,
						Text:          "请基于 WinTraceLens 采集结果判断当前主机是否存在挖矿、蠕虫、远控或持久化风险，并给出下一步排查建议。",
						VScroll:       true,
						CompactHeight: false,
						MinSize:       Size{Height: 120},
					},
				},
			},
			Composite{
				StretchFactor: 1,
				Background:    SolidColorBrush{Color: walk.RGB(255, 255, 255)},
				Layout:        VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
				Children: []Widget{
					Label{Text: "分析结果", Font: Font{Family: "Microsoft YaHei UI", PointSize: 9, Bold: true}, TextColor: walk.RGB(28, 40, 56)},
					TextEdit{
						AssignTo:      &a.aiOutput,
						ReadOnly:      true,
						VScroll:       true,
						HScroll:       false,
						CompactHeight: false,
						StretchFactor: 1,
					},
					Label{Text: "追问", Font: Font{Family: "Microsoft YaHei UI", PointSize: 9, Bold: true}, TextColor: walk.RGB(28, 40, 56)},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
						TextEdit{AssignTo: &a.aiFollowUp, VScroll: true, CompactHeight: false, MinSize: Size{Height: 54}, StretchFactor: 1},
						PushButton{Text: "发送追问", MinSize: Size{Width: 94}, OnClicked: a.sendAIFollowUp},
					}},
				},
			},
		},
	}
}

func (a *legacyApp) table(columns []tableColumn, model *tableModel) Widget {
	return a.assignedTable(columns, model, nil)
}

func (a *legacyApp) assignedTable(columns []tableColumn, model *tableModel, assignTo **walk.TableView) Widget {
	return a.assignedTableWithHandler(columns, model, assignTo, nil)
}

func (a *legacyApp) assignedTableWithHandler(columns []tableColumn, model *tableModel, assignTo **walk.TableView, onCurrent walk.EventHandler) Widget {
	return a.assignedTableWithHandlerAndMenu(columns, model, assignTo, onCurrent, nil)
}

func (a *legacyApp) assignedTableWithHandlerAndMenu(columns []tableColumn, model *tableModel, assignTo **walk.TableView, onCurrent walk.EventHandler, menu []MenuItem) Widget {
	return a.assignedTableWithMinHeight(columns, model, assignTo, onCurrent, menu, 0)
}

func (a *legacyApp) assignedTableWithMinHeight(columns []tableColumn, model *tableModel, assignTo **walk.TableView, onCurrent walk.EventHandler, menu []MenuItem, minHeight int) Widget {
	minSize := Size{}
	if minHeight > 0 {
		minSize = Size{Height: minHeight}
	}
	return TableView{
		AssignTo:                    assignTo,
		Background:                  SolidColorBrush{Color: walk.RGB(255, 255, 255)},
		ContextMenuItems:            menu,
		Columns:                     toTableViewColumns(columns),
		Model:                       model,
		MinSize:                     minSize,
		AlternatingRowBG:            true,
		LastColumnStretched:         false,
		SelectionHiddenWithoutFocus: false,
		StretchFactor:               1,
		OnCurrentIndexChanged:       onCurrent,
	}
}

func (a *legacyApp) repaintAfterNavigation() {
	a.repaintCurrentTables()
	if a.mainTabs != nil {
		a.redrawWindow(a.mainTabs)
	}
	if a.mw != nil {
		a.redrawWindow(a.mw)
	}
}

func (a *legacyApp) scheduleRepaintAfterNavigation() {
	go func() {
		time.Sleep(40 * time.Millisecond)
		if a.mw == nil {
			return
		}
		a.mw.Synchronize(a.repaintAfterNavigation)
	}()
}

func (a *legacyApp) repaintCurrentTables() {
	var tables []*walk.TableView
	switch currentIndex(a.mainTabs) {
	case 0:
		tables = []*walk.TableView{a.processView, a.moduleView, a.connView}
	case 1:
		tables = []*walk.TableView{a.hostView}
	case 2:
		tables = []*walk.TableView{a.findingView}
	case 3:
		tables = []*walk.TableView{a.eventView}
	case 4:
		tables = []*walk.TableView{a.historyView}
	case 5:
		tables = []*walk.TableView{a.fileTraceView}
	default:
		tables = []*walk.TableView{
			a.processView,
			a.moduleView,
			a.connView,
			a.hostView,
			a.findingView,
			a.eventView,
			a.historyView,
			a.fileTraceView,
		}
	}
	for _, table := range tables {
		a.repaintTable(table)
	}
}

func (a *legacyApp) repaintAllTables() {
	for _, table := range []*walk.TableView{
		a.processView,
		a.moduleView,
		a.connView,
		a.hostView,
		a.findingView,
		a.eventView,
		a.historyView,
		a.fileTraceView,
	} {
		a.repaintTable(table)
	}
}

func (a *legacyApp) repaintTable(table *walk.TableView) {
	if table == nil {
		return
	}
	_ = table.Invalidate()
	table.RequestLayout()
	a.redrawWindow(table)
}

func (a *legacyApp) redrawWindow(window walk.Window) {
	if window == nil || window.Handle() == 0 {
		return
	}
	window.RequestLayout()
	_ = window.Invalidate()
	win.RedrawWindow(window.Handle(), nil, win.HRGN(0), win.RDW_INVALIDATE|win.RDW_ERASE|win.RDW_ALLCHILDREN|win.RDW_UPDATENOW|win.RDW_ERASENOW)
}

func (a *legacyApp) onMainTabChanged() {
	if a.mainTabs == nil {
		return
	}
	if a.navList != nil && a.navList.CurrentIndex() != a.mainTabs.CurrentIndex() {
		_ = a.navList.SetCurrentIndex(a.mainTabs.CurrentIndex())
	}
	switch a.mainTabs.CurrentIndex() {
	case 0:
		if !a.processStarted {
			a.refreshProcesses()
		}
	case 1:
		if !a.hostStarted {
			a.refreshHost()
		}
	case 2:
		if !a.findingStarted {
			a.refreshFindings()
		}
	case 3:
		if !a.eventStarted {
			a.refreshEvents()
		}
	case 4:
		if !a.historyStarted {
			a.refreshHistory()
		}
	case 5:
		if !a.fileTraceStarted {
			a.refreshFileTrace()
		}
	}
	a.repaintAfterNavigation()
	a.scheduleRepaintAfterNavigation()
}

func (a *legacyApp) onNavChanged() {
	if a.navList == nil || a.mainTabs == nil {
		return
	}
	index := a.navList.CurrentIndex()
	if index < 0 || index >= len(navItems) || a.mainTabs.CurrentIndex() == index {
		return
	}
	a.repaintAfterNavigation()
	_ = a.mainTabs.SetCurrentIndex(index)
}

func (a *legacyApp) onHostTabChanged() {
	if !a.hostStarted {
		return
	}
	a.refreshVisibleHostTable()
}

func (a *legacyApp) refreshProcesses() {
	a.processStarted = true
	a.setStatus("正在采集进程、MD5、签名和连接数...")
	go func() {
		items, err := process.Collect(process.Options{HashLimitBytes: a.hashLimitBytes})
		rows := processRows(items)
		a.mw.Synchronize(func() {
			if err != nil {
				a.showError("进程采集失败", err)
				a.setStatus("进程采集失败。")
				return
			}
			a.processRows = rows
			a.setSummary(a.processSummary, processSummaryText(items))
			a.applyProcessFilter()
			a.clearProcessDetails("请选择一个进程查看模块列表和网络连接。")
			a.setStatus(fmt.Sprintf("进程信息完成：%d 条。", len(rows)))
		})
	}()
}

func (a *legacyApp) selectFirstProcessRow() {
	if a.processView == nil || a.processModel == nil || len(a.processModel.rows) == 0 {
		a.clearProcessDetails("未选择进程。")
		return
	}
	_ = a.processView.SetCurrentIndex(0)
	a.onProcessSelected()
}

func (a *legacyApp) onProcessSelected() {
	row := a.selectedProcessRow()
	if len(row) == 0 {
		a.clearProcessDetails("未选择进程。")
		return
	}
	pidValue, err := strconv.ParseUint(valueAt(row, 0), 10, 32)
	if err != nil {
		a.clearProcessDetails("无法识别选中进程的 PID。")
		return
	}
	a.loadProcessDetails(uint32(pidValue), valueAt(row, 1), false)
}

func (a *legacyApp) selectedProcessRow() []string {
	if a.processView == nil || a.processModel == nil {
		return nil
	}
	index := a.processView.CurrentIndex()
	if index < 0 || index >= len(a.processModel.rows) {
		return nil
	}
	return a.processModel.rows[index]
}

func (a *legacyApp) refreshSelectedProcessDetails() {
	row := a.selectedProcessRow()
	if len(row) == 0 {
		a.clearProcessDetails("请先选择一个进程。")
		return
	}
	pidValue, err := strconv.ParseUint(valueAt(row, 0), 10, 32)
	if err != nil {
		a.clearProcessDetails("无法识别选中进程的 PID。")
		return
	}
	a.loadProcessDetails(uint32(pidValue), valueAt(row, 1), true)
}

func (a *legacyApp) loadProcessDetails(pid uint32, name string, force bool) {
	if !force && a.hasSelection && a.selectedPID == pid {
		return
	}
	a.selectedPID = pid
	a.selectedName = name
	a.hasSelection = true
	a.detailSeq++
	seq := a.detailSeq
	a.moduleModel.SetRows(nil)
	a.connModel.SetRows(nil)
	a.repaintTable(a.moduleView)
	a.repaintTable(a.connView)
	if a.processDetail != nil {
		_ = a.processDetail.SetText(fmt.Sprintf("正在读取 %s (PID %d) 的模块和网络连接...", name, pid))
	}
	go func() {
		modules, moduleErr := process.Modules(pid, process.Options{HashLimitBytes: a.hashLimitBytes})
		connections, connectionErr := process.Connections(pid)
		moduleRows := moduleRows(modules)
		connRows := connectionRows(connections)
		if moduleErr != nil {
			moduleRows = append(moduleRows, []string{name, "", "", "", "", "", moduleErr.Error()})
		}
		if connectionErr != nil {
			connRows = append(connRows, []string{"错误", "", "", connectionErr.Error(), "", "", ""})
		}
		a.mw.Synchronize(func() {
			if seq != a.detailSeq {
				return
			}
			a.moduleRows = moduleRows
			a.connRows = connRows
			a.moduleModel.SetRows(moduleRows)
			a.connModel.SetRows(connRows)
			a.repaintTable(a.moduleView)
			a.repaintTable(a.connView)
			if a.processDetail != nil {
				_ = a.processDetail.SetText(processDetailSummary(pid, name, modules, connections, moduleErr, connectionErr))
			}
			a.setStatus(fmt.Sprintf("进程详情完成：%s (PID %d)，模块 %d，连接 %d。", name, pid, len(modules), len(connections)))
		})
	}()
}

func (a *legacyApp) clearProcessDetails(text string) {
	a.hasSelection = false
	a.selectedPID = 0
	a.selectedName = ""
	a.detailSeq++
	a.moduleRows = nil
	a.connRows = nil
	if a.moduleModel != nil {
		a.moduleModel.SetRows(nil)
	}
	if a.connModel != nil {
		a.connModel.SetRows(nil)
	}
	a.repaintTable(a.moduleView)
	a.repaintTable(a.connView)
	if a.processDetail != nil {
		_ = a.processDetail.SetText(text)
	}
}

func (a *legacyApp) exportSelectedModules() {
	if !a.hasSelection {
		a.setStatus("请先选择一个进程。")
		return
	}
	a.exportModel(fmt.Sprintf("modules-%d", a.selectedPID), a.moduleModel)
}

func (a *legacyApp) exportSelectedConnections() {
	if !a.hasSelection {
		a.setStatus("请先选择一个进程。")
		return
	}
	a.exportModel(fmt.Sprintf("connections-%d", a.selectedPID), a.connModel)
}

func (a *legacyApp) processContextMenu() []MenuItem {
	return []MenuItem{
		Action{Text: "复制 PID", OnTriggered: func() { a.copyTableColumn(a.processView, a.processModel, 0, "PID") }},
		Action{Text: "复制进程名", OnTriggered: func() { a.copyTableColumn(a.processView, a.processModel, 1, "进程名") }},
		Action{Text: "复制 MD5", OnTriggered: func() { a.copyTableColumn(a.processView, a.processModel, 7, "MD5") }},
		Action{Text: "复制路径", OnTriggered: func() { a.copyTableColumn(a.processView, a.processModel, 12, "路径") }},
		Separator{},
		Action{Text: "复制整行", OnTriggered: func() { a.copyTableRow(a.processView, a.processModel, "进程信息") }},
	}
}

func (a *legacyApp) moduleContextMenu() []MenuItem {
	return []MenuItem{
		Action{Text: "复制模块名", OnTriggered: func() { a.copyTableColumn(a.moduleView, a.moduleModel, 0, "模块名") }},
		Action{Text: "复制 MD5", OnTriggered: func() { a.copyTableColumn(a.moduleView, a.moduleModel, 1, "MD5") }},
		Action{Text: "复制路径", OnTriggered: func() { a.copyTableColumn(a.moduleView, a.moduleModel, 5, "路径") }},
		Action{Text: "复制基址", OnTriggered: func() { a.copyTableColumn(a.moduleView, a.moduleModel, 3, "基址") }},
		Separator{},
		Action{Text: "复制整行", OnTriggered: func() { a.copyTableRow(a.moduleView, a.moduleModel, "模块信息") }},
	}
}

func (a *legacyApp) connectionContextMenu() []MenuItem {
	return []MenuItem{
		Action{Text: "复制本地地址", OnTriggered: func() { a.copyTableColumn(a.connView, a.connModel, 2, "本地地址") }},
		Action{Text: "复制远程地址", OnTriggered: func() { a.copyTableColumn(a.connView, a.connModel, 3, "远程地址") }},
		Action{Text: "复制远程类型", OnTriggered: func() { a.copyTableColumn(a.connView, a.connModel, 1, "远程类型") }},
		Action{Text: "复制状态", OnTriggered: func() { a.copyTableColumn(a.connView, a.connModel, 4, "状态") }},
		Separator{},
		Action{Text: "复制整行", OnTriggered: func() { a.copyTableRow(a.connView, a.connModel, "网络连接") }},
	}
}

func (a *legacyApp) eventContextMenu() []MenuItem {
	return []MenuItem{
		Action{Text: "查看详情", OnTriggered: func() { a.showTableRowDetails(a.eventView, a.eventModel, "事件日志详情") }},
		Action{Text: "复制详情", OnTriggered: func() { a.copyTableColumn(a.eventView, a.eventModel, 10, "详情") }},
		Action{Text: "保存详情", OnTriggered: func() { a.saveTableRowDetails(a.eventView, a.eventModel, "event-detail") }},
		Separator{},
		Action{Text: "复制整行", OnTriggered: func() { a.copyTableRow(a.eventView, a.eventModel, "事件日志") }},
	}
}

func (a *legacyApp) historyContextMenu() []MenuItem {
	return []MenuItem{
		Action{Text: "查看详情", OnTriggered: func() { a.showTableRowDetails(a.historyView, a.historyModel, "历史通信详情") }},
		Action{Text: "复制远程/DNS", OnTriggered: func() { a.copyHistoryTarget() }},
		Action{Text: "复制详情", OnTriggered: func() { a.copyTableColumn(a.historyView, a.historyModel, 11, "详情") }},
		Action{Text: "保存详情", OnTriggered: func() { a.saveTableRowDetails(a.historyView, a.historyModel, "history-detail") }},
		Separator{},
		Action{Text: "复制整行", OnTriggered: func() { a.copyTableRow(a.historyView, a.historyModel, "历史通信") }},
	}
}

func (a *legacyApp) fileTraceContextMenu() []MenuItem {
	return []MenuItem{
		Action{Text: "查看详情", OnTriggered: func() { a.showTableRowDetails(a.fileTraceView, a.fileTraceModel, "文件痕迹详情") }},
		Action{Text: "复制路径", OnTriggered: func() { a.copyTableColumn(a.fileTraceView, a.fileTraceModel, 10, "路径") }},
		Action{Text: "复制原因", OnTriggered: func() { a.copyTableColumn(a.fileTraceView, a.fileTraceModel, 4, "原因") }},
		Action{Text: "保存详情", OnTriggered: func() { a.saveTableRowDetails(a.fileTraceView, a.fileTraceModel, "file-trace-detail") }},
		Separator{},
		Action{Text: "复制整行", OnTriggered: func() { a.copyTableRow(a.fileTraceView, a.fileTraceModel, "文件痕迹") }},
	}
}

func (a *legacyApp) copyTableColumn(view *walk.TableView, model *tableModel, col int, label string) {
	row := currentTableRow(view, model)
	if len(row) == 0 {
		a.setStatus("请先选择一行。")
		return
	}
	value := strings.TrimSpace(valueAt(row, col))
	if value == "" || value == "-" {
		a.setStatus(label + " 为空，未复制。")
		return
	}
	if err := walk.Clipboard().SetText(value); err != nil {
		a.showError("复制失败", err)
		return
	}
	a.setStatus("已复制 " + label + "：" + compactStatusValue(value))
}

func (a *legacyApp) copyTableRow(view *walk.TableView, model *tableModel, label string) {
	row := currentTableRow(view, model)
	if len(row) == 0 {
		a.setStatus("请先选择一行。")
		return
	}
	var parts []string
	headers := model.Headers()
	for i, header := range headers {
		value := strings.TrimSpace(valueAt(row, i))
		if value == "" {
			continue
		}
		parts = append(parts, header+": "+value)
	}
	text := strings.Join(parts, "\r\n")
	if strings.TrimSpace(text) == "" {
		a.setStatus(label + " 为空，未复制。")
		return
	}
	if err := walk.Clipboard().SetText(text); err != nil {
		a.showError("复制失败", err)
		return
	}
	a.setStatus("已复制 " + label + "整行。")
}

func (a *legacyApp) showTableRowDetails(view *walk.TableView, model *tableModel, title string) {
	text := a.tableRowDetailText(view, model)
	if strings.TrimSpace(text) == "" {
		a.setStatus("请先选择一行。")
		return
	}
	walk.MsgBox(a.mw, title, text, walk.MsgBoxIconInformation)
}

func (a *legacyApp) saveTableRowDetails(view *walk.TableView, model *tableModel, name string) {
	text := a.tableRowDetailText(view, model)
	if strings.TrimSpace(text) == "" {
		a.setStatus("请先选择一行。")
		return
	}
	dlg := walk.FileDialog{
		Title:    "保存详情",
		Filter:   "文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
		FilePath: fmt.Sprintf("%s-%s.txt", name, time.Now().Format("20060102-150405")),
	}
	ok, err := dlg.ShowSave(a.mw)
	if err != nil {
		a.showError("保存详情失败", err)
		return
	}
	if !ok {
		return
	}
	path := dlg.FilePath
	if !strings.EqualFold(filepath.Ext(path), ".txt") {
		path += ".txt"
	}
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		a.showError("保存详情失败", err)
		return
	}
	a.setStatus("详情已保存：" + path)
}

func (a *legacyApp) tableRowDetailText(view *walk.TableView, model *tableModel) string {
	row := currentTableRow(view, model)
	if len(row) == 0 || model == nil {
		return ""
	}
	headers := model.Headers()
	var lines []string
	for i, header := range headers {
		value := strings.TrimSpace(valueAt(row, i))
		if value == "" {
			continue
		}
		lines = append(lines, header+": "+value)
	}
	return strings.Join(lines, "\r\n")
}

func (a *legacyApp) copyHistoryTarget() {
	row := currentTableRow(a.historyView, a.historyModel)
	if len(row) == 0 {
		a.setStatus("请先选择一行。")
		return
	}
	value := strings.TrimSpace(valueAt(row, 7))
	if value == "" {
		value = strings.TrimSpace(valueAt(row, 8))
	}
	if value == "" {
		a.setStatus("远程/DNS 为空，未复制。")
		return
	}
	if err := walk.Clipboard().SetText(value); err != nil {
		a.showError("复制失败", err)
		return
	}
	a.setStatus("已复制远程/DNS：" + compactStatusValue(value))
}

func (a *legacyApp) refreshHost() {
	a.hostStarted = true
	a.setStatus("正在采集服务、计划任务、启动项、用户和镜像劫持...")
	go func() {
		snapshot, err := host.Collect(host.Options{HashLimitBytes: a.hashLimitBytes})
		a.mw.Synchronize(func() {
			if err != nil {
				a.showError("主机信息采集失败", err)
				a.setStatus("主机信息采集失败。")
				return
			}
			a.serviceRows = serviceRows(snapshot.Services)
			a.taskRows = taskRows(snapshot.ScheduledTasks)
			a.startupRows = startupRows(snapshot.StartupItems)
			a.userRows = userRows(snapshot.Users)
			a.ifeoRows = ifeoRows(snapshot.ImageHijacks)
			a.persistenceRows = persistenceRows(snapshot.PersistenceItems)
			a.setSummary(a.hostSummary, hostSummaryText(snapshot))
			a.rebuildHostRows()
			a.refreshVisibleHostTable()
			warn := ""
			if len(snapshot.CollectionErrors) > 0 {
				warn = fmt.Sprintf("，采集警告 %d 条", len(snapshot.CollectionErrors))
			}
			a.setStatus(fmt.Sprintf("主机信息完成：服务 %d，计划任务 %d，启动项 %d，用户 %d，镜像劫持 %d，持久化 %d%s。", len(a.serviceRows), len(a.taskRows), len(a.startupRows), len(a.userRows), len(a.ifeoRows), len(a.persistenceRows), warn))
		})
	}()
}

func (a *legacyApp) refreshFindings() {
	a.findingStarted = true
	a.setStatus("正在进行关注项分析...")
	go func() {
		processes, procErr := process.Collect(process.Options{HashLimitBytes: a.hashLimitBytes})
		snapshot, hostErr := host.Collect(host.Options{HashLimitBytes: a.hashLimitBytes})
		var err error
		if procErr != nil {
			err = fmt.Errorf("进程采集失败: %w", procErr)
		} else if hostErr != nil {
			err = fmt.Errorf("主机信息采集失败: %w", hostErr)
		}
		findings := analysis.BuildFindings(processes, snapshot)
		rows := findingRows(findings)
		a.mw.Synchronize(func() {
			if err != nil {
				a.showError("关注项分析失败", err)
				a.setStatus("关注项分析失败。")
				return
			}
			a.findingRows = rows
			a.setSummary(a.findingSummary, findingSummaryText(findings))
			a.applyFindingFilter()
			a.setStatus(fmt.Sprintf("关注项完成：%d 条。", len(rows)))
		})
	}()
}

func (a *legacyApp) refreshEvents() {
	opts, err := a.eventOptions()
	if err != nil {
		a.showError("事件日志参数错误", err)
		return
	}
	a.eventStarted = true
	a.setStatus("正在读取事件日志...")
	go func() {
		snapshot, err := securitylog.Collect(opts)
		rows := eventRows(snapshot.Events)
		warnings := eventWarningRows(snapshot.GeneratedAt, snapshot.CollectionErrors)
		a.mw.Synchronize(func() {
			if err != nil {
				a.showError("事件日志读取失败", err)
				a.setStatus("事件日志读取失败。")
				return
			}
			a.eventRows = rows
			a.eventWarnings = warnings
			a.setSummary(a.eventSummary, eventSummaryText(snapshot.Events, snapshot.CollectionErrors))
			a.applyEventFilter()
			warn := ""
			if len(snapshot.CollectionErrors) > 0 {
				warn = fmt.Sprintf("，采集警告 %d 条", len(snapshot.CollectionErrors))
			}
			a.setStatus(fmt.Sprintf("事件日志完成：%d 条%s。", len(rows), warn))
		})
	}()
}

func (a *legacyApp) refreshHistory() {
	opts, err := a.historyOptions()
	if err != nil {
		a.showError("历史通信参数错误", err)
		return
	}
	a.historyStarted = true
	a.setStatus("正在读取历史通信记录...")
	go func() {
		snapshot, err := history.Collect(opts)
		rows := historyRows(snapshot.Records)
		warnings := historyWarningRows(snapshot.GeneratedAt, snapshot.CollectionErrors)
		a.mw.Synchronize(func() {
			if err != nil {
				a.showError("历史通信读取失败", err)
				a.setStatus("历史通信读取失败。")
				return
			}
			a.historyRows = rows
			a.historyWarnings = warnings
			a.setSummary(a.historySummary, historySummaryText(snapshot.Records, snapshot.CollectionErrors))
			a.applyHistoryFilter()
			warn := ""
			if len(snapshot.CollectionErrors) > 0 {
				warn = fmt.Sprintf("，采集提示 %d 条", len(snapshot.CollectionErrors))
			}
			a.setStatus(fmt.Sprintf("历史通信完成：%d 条%s。", len(rows), warn))
		})
	}()
}

func (a *legacyApp) refreshFileTrace() {
	opts, err := a.fileTraceOptions()
	if err != nil {
		a.showError("文件痕迹参数错误", err)
		return
	}
	a.fileTraceStarted = true
	a.setStatus("正在扫描最近修改文件、最近运行文件和 Temp 可疑文件...")
	go func() {
		snapshot, err := filetrace.Collect(opts)
		rows := fileTraceRows(snapshot.Records)
		warnings := fileTraceWarningRows(snapshot.GeneratedAt, snapshot.CollectionErrors)
		a.mw.Synchronize(func() {
			if err != nil {
				a.showError("文件痕迹扫描失败", err)
				a.setStatus("文件痕迹扫描失败。")
				return
			}
			a.fileTraceRows = rows
			a.fileTraceWarnings = warnings
			a.setSummary(a.fileTraceSummary, fileTraceSummaryText(snapshot.Records, snapshot.CollectionErrors))
			a.applyFileTraceFilter()
			warn := ""
			if len(snapshot.CollectionErrors) > 0 {
				warn = fmt.Sprintf("，采集提示 %d 条", len(snapshot.CollectionErrors))
			}
			a.setStatus(fmt.Sprintf("文件痕迹完成：%d 条%s。", len(rows), warn))
		})
	}()
}

func (a *legacyApp) applyProcessFilter() {
	rows := filterRows(a.processRows, lineText(a.processSearch))
	a.processModel.SetRows(rows)
	a.repaintTable(a.processView)
	if len(rows) == 0 {
		a.clearProcessDetails("当前筛选没有匹配进程。")
	}
}

func (a *legacyApp) applyHostFilter() {
	a.hostModel.SetRows(a.filteredHostRows())
	a.repaintTable(a.hostView)
}

func (a *legacyApp) refreshVisibleHostTable() {
	a.hostModel.SetRows(a.filteredHostRows())
	a.repaintTable(a.hostView)
}

func (a *legacyApp) setHostKind(kind string) {
	if a.hostKind == kind {
		return
	}
	a.hostKind = kind
	a.refreshVisibleHostTable()
	a.setStatus("主机信息视图：" + hostKindName(kind))
}

func (a *legacyApp) filteredHostRows() [][]string {
	rows := a.hostRowsForKind(a.hostKind)
	if strings.TrimSpace(lineText(a.hostSearch)) == "" {
		return rows
	}
	return filterRows(rows, lineText(a.hostSearch))
}

func (a *legacyApp) hostRowsForKind(kind string) [][]string {
	switch kind {
	case "tasks":
		return a.hostTaskRows
	case "startup":
		return a.hostStartupRows
	case "users":
		return a.hostUserRows
	case "ifeo":
		return a.hostIFEORows
	case "persistence":
		return a.hostPersistenceRows
	case "all":
		return a.hostAllRows
	default:
		return a.hostServiceRows
	}
}

func (a *legacyApp) rebuildHostRows() {
	a.hostServiceRows = hostRowsFromServices(a.serviceRows)
	a.hostTaskRows = hostRowsFromTasks(a.taskRows)
	a.hostStartupRows = hostRowsFromStartup(a.startupRows)
	a.hostUserRows = hostRowsFromUsers(a.userRows)
	a.hostIFEORows = hostRowsFromIFEO(a.ifeoRows)
	a.hostPersistenceRows = hostRowsFromPersistence(a.persistenceRows)
	a.hostAllRows = appendRows(nil, a.hostServiceRows)
	a.hostAllRows = appendRows(a.hostAllRows, a.hostTaskRows)
	a.hostAllRows = appendRows(a.hostAllRows, a.hostStartupRows)
	a.hostAllRows = appendRows(a.hostAllRows, a.hostUserRows)
	a.hostAllRows = appendRows(a.hostAllRows, a.hostIFEORows)
	a.hostAllRows = appendRows(a.hostAllRows, a.hostPersistenceRows)
}

func hostKindName(kind string) string {
	switch kind {
	case "tasks":
		return "计划任务"
	case "startup":
		return "启动项"
	case "users":
		return "用户"
	case "ifeo":
		return "镜像劫持"
	case "persistence":
		return "持久化"
	case "all":
		return "全部"
	default:
		return "服务"
	}
}

func (a *legacyApp) applyFindingFilter() {
	a.findingModel.SetRows(filterRows(a.findingRows, lineText(a.findingSearch)))
	a.repaintTable(a.findingView)
}

func (a *legacyApp) applyEventFilter() {
	rows := filterRows(a.eventRowsForCategory(), lineText(a.eventSearch))
	a.eventModel.SetRows(rows)
	a.repaintTable(a.eventView)
}

func (a *legacyApp) applyHistoryFilter() {
	rows := copyRows(a.historyRows)
	rows = appendRows(rows, a.historyWarnings)
	a.historyModel.SetRows(filterRows(rows, lineText(a.historySearch)))
	a.repaintTable(a.historyView)
}

func (a *legacyApp) applyFileTraceFilter() {
	rows := copyRows(a.fileTraceRows)
	rows = appendRows(rows, a.fileTraceWarnings)
	a.fileTraceModel.SetRows(filterRows(rows, lineText(a.fileTraceSearch)))
	a.repaintTable(a.fileTraceView)
}

func (a *legacyApp) setEventCategory(category string) {
	if strings.TrimSpace(category) == "" {
		category = "all"
	}
	a.eventCategory = category
	a.applyEventFilter()
	count := 0
	if a.eventModel != nil {
		count = len(a.eventModel.rows)
	}
	a.setStatus(fmt.Sprintf("事件日志分类：%s，显示 %d 条。", eventCategoryName(category), count))
}

func (a *legacyApp) eventRowsForCategory() [][]string {
	if a.eventCategory == "" || a.eventCategory == "all" {
		rows := copyRows(a.eventRows)
		rows = appendRows(rows, a.eventWarnings)
		return rows
	}
	rows := make([][]string, 0, len(a.eventRows))
	for _, row := range a.eventRows {
		if eventRowMatchesCategory(row, a.eventCategory) {
			rows = append(rows, append([]string(nil), row...))
		}
	}
	return rows
}

func (a *legacyApp) eventOptions() (securitylog.Options, error) {
	start, err := parseDate(lineText(a.eventStart), false)
	if err != nil {
		return securitylog.Options{}, fmt.Errorf("开始日期: %w", err)
	}
	end, err := parseDate(lineText(a.eventEnd), true)
	if err != nil {
		return securitylog.Options{}, fmt.Errorf("结束日期: %w", err)
	}
	if !start.IsZero() && !end.IsZero() && end.Before(start) {
		return securitylog.Options{}, fmt.Errorf("结束日期不能早于开始日期")
	}
	maxRecords := 500
	if raw := lineText(a.eventMax); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return securitylog.Options{}, fmt.Errorf("条数必须是正整数")
		}
		maxRecords = parsed
	}
	return securitylog.Options{StartTime: start, EndTime: end, MaxRecords: maxRecords}, nil
}

func (a *legacyApp) historyOptions() (history.Options, error) {
	start, err := parseDate(lineText(a.historyStart), false)
	if err != nil {
		return history.Options{}, fmt.Errorf("开始日期: %w", err)
	}
	end, err := parseDate(lineText(a.historyEnd), true)
	if err != nil {
		return history.Options{}, fmt.Errorf("结束日期: %w", err)
	}
	if !start.IsZero() && !end.IsZero() && end.Before(start) {
		return history.Options{}, fmt.Errorf("结束日期不能早于开始日期")
	}
	maxRecords := 500
	if raw := lineText(a.historyMax); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return history.Options{}, fmt.Errorf("条数必须是正整数")
		}
		maxRecords = parsed
	}
	return history.Options{StartTime: start, EndTime: end, MaxRecords: maxRecords}, nil
}

func (a *legacyApp) fileTraceOptions() (filetrace.Options, error) {
	hours := 72
	if raw := lineText(a.fileTraceHours); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return filetrace.Options{}, fmt.Errorf("最近小时必须是正整数")
		}
		hours = parsed
	}
	maxRecords := 500
	if raw := lineText(a.fileTraceMax); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return filetrace.Options{}, fmt.Errorf("条数必须是正整数")
		}
		maxRecords = parsed
	}
	return filetrace.Options{
		Hours:         hours,
		MaxRecords:    maxRecords,
		ModifiedRoots: splitPathList(lineText(a.fileTraceRoots)),
	}, nil
}

func (a *legacyApp) onAIProviderChanged() {
	provider := aiProviderValue(comboText(a.aiProvider))
	if a.aiModel != nil {
		_ = a.aiModel.SetText(defaultAIModel(provider))
	}
	if a.aiBaseURL != nil {
		_ = a.aiBaseURL.SetText(defaultAIBaseURL(provider))
	}
}

func (a *legacyApp) startAIAnalysis() {
	question := strings.TrimSpace(textEditText(a.aiQuestion))
	if question == "" {
		a.setStatus("请先输入 AI 分析问题。")
		return
	}
	a.runAIRequest(question, true)
}

func (a *legacyApp) sendAIFollowUp() {
	question := strings.TrimSpace(textEditText(a.aiFollowUp))
	if question == "" {
		a.setStatus("请先输入追问内容。")
		return
	}
	a.runAIRequest(question, false)
}

func (a *legacyApp) runAIRequest(question string, reset bool) {
	if a.aiBusy {
		a.setStatus("AI 分析正在执行，请等待当前请求完成。")
		return
	}
	provider := aiProviderValue(comboText(a.aiProvider))
	model := strings.TrimSpace(comboText(a.aiModel))
	if model == "" {
		model = defaultAIModel(provider)
	}
	apiKey := lineText(a.aiAPIKey)
	if apiKey == "" {
		a.setStatus("请先填写 API Key。")
		return
	}

	sections := a.aiSelectedSections()
	if len(sections) == 0 {
		a.setStatus("请至少选择一个证据范围。")
		return
	}

	req := aianalysis.AnalyzeRequest{
		Provider:       provider,
		Model:          model,
		APIKey:         apiKey,
		BaseURL:        lineText(a.aiBaseURL),
		Sections:       sections,
		MaxItems:       80,
		TimeoutSeconds: 120,
	}

	var messages []aianalysis.Message
	if reset || len(a.aiChat) == 0 {
		req.Question = question
		messages = []aianalysis.Message{{Role: "user", Content: question}}
	} else {
		messages = append([]aianalysis.Message(nil), a.aiChat...)
		messages = append(messages, aianalysis.Message{Role: "user", Content: question})
		req.Messages = messages
		req.IncludeEvidence = false
	}

	a.aiBusy = true
	a.setSummary(a.aiSummary, "正在请求 AI 分析，旧系统上证据采集和网络请求可能需要几十秒。")
	a.setStatus("AI 分析请求已开始...")
	go func(req aianalysis.AnalyzeRequest, messages []aianalysis.Message) {
		resp, err := aianalysis.Analyze(context.Background(), req, aianalysis.Options{HashLimitBytes: a.hashLimitBytes})
		a.mw.Synchronize(func() {
			a.aiBusy = false
			if err != nil {
				a.showError("AI 分析失败", err)
				a.setSummary(a.aiSummary, "AI 分析失败。")
				a.setStatus("AI 分析失败。")
				return
			}
			a.aiChat = append(messages, aianalysis.Message{Role: "assistant", Content: resp.Answer})
			a.aiLastTranscript = renderAITranscript(a.aiChat, resp)
			if a.aiOutput != nil {
				_ = a.aiOutput.SetText(a.aiLastTranscript)
			}
			if !reset && a.aiFollowUp != nil {
				_ = a.aiFollowUp.SetText("")
			}
			a.setSummary(a.aiSummary, aiSummaryText(resp))
			a.setStatus(fmt.Sprintf("AI 分析完成：%s / %s。", resp.Provider, resp.Model))
		})
	}(req, messages)
}

func (a *legacyApp) aiSelectedSections() []string {
	var sections []string
	if checkBoxChecked(a.aiSecProcesses) {
		sections = append(sections, "processes")
	}
	if checkBoxChecked(a.aiSecFindings) {
		sections = append(sections, "findings")
	}
	if checkBoxChecked(a.aiSecHost) {
		sections = append(sections, "host")
	}
	if checkBoxChecked(a.aiSecFileTrace) {
		sections = append(sections, "filetrace")
	}
	if checkBoxChecked(a.aiSecHistory) {
		sections = append(sections, "history")
	}
	if checkBoxChecked(a.aiSecSecurity) {
		sections = append(sections, "security")
	}
	return sections
}

func (a *legacyApp) copyAITranscript() {
	text := strings.TrimSpace(a.aiLastTranscript)
	if text == "" {
		text = strings.TrimSpace(textEditText(a.aiOutput))
	}
	if text == "" {
		a.setStatus("当前没有可复制的 AI 分析结果。")
		return
	}
	if err := walk.Clipboard().SetText(text); err != nil {
		a.showError("复制失败", err)
		return
	}
	a.setStatus("已复制 AI 分析结果。")
}

func (a *legacyApp) clearAIConversation() {
	if a.aiBusy {
		a.setStatus("AI 请求未完成，暂不能清空。")
		return
	}
	a.aiChat = nil
	a.aiLastTranscript = ""
	if a.aiOutput != nil {
		_ = a.aiOutput.SetText("")
	}
	if a.aiFollowUp != nil {
		_ = a.aiFollowUp.SetText("")
	}
	a.setSummary(a.aiSummary, "对话已清空，API Key 和模型配置仍保留。")
	a.setStatus("AI 对话已清空。")
}

func parseDate(value string, endOfDay bool) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("格式应为 YYYY-MM-DD")
	}
	if endOfDay {
		return parsed.Add(24*time.Hour - time.Second), nil
	}
	return parsed, nil
}

func (a *legacyApp) exportCurrentHostTable() {
	a.exportModel("host-"+a.hostKind, a.hostModel)
}

func (a *legacyApp) exportEvidencePackage() {
	opts, err := a.eventOptions()
	if err != nil {
		a.showError("事件日志参数错误", err)
		return
	}
	dlg := walk.FileDialog{
		Title:    "导出取证包",
		Filter:   "ZIP 文件 (*.zip)|*.zip|所有文件 (*.*)|*.*",
		FilePath: defaultPackageName(),
	}
	ok, err := dlg.ShowSave(a.mw)
	if err != nil {
		a.showError("导出取证包失败", err)
		return
	}
	if !ok {
		return
	}
	path := ensureZIPExt(dlg.FilePath)
	a.setStatus("正在导出取证包，后台采集进程、主机信息、关注项和事件日志...")
	go func() {
		err := writeEvidencePackage(path, opts, a.hashLimitBytes)
		a.mw.Synchronize(func() {
			if err != nil {
				a.showError("导出取证包失败", err)
				a.setStatus("取证包导出失败。")
				return
			}
			a.setStatus("取证包已导出：" + path)
		})
	}()
}

func (a *legacyApp) exportModel(name string, model *tableModel) {
	if model == nil {
		return
	}
	dlg := walk.FileDialog{
		Title:    "导出 CSV",
		Filter:   "CSV 文件 (*.csv)|*.csv|所有文件 (*.*)|*.*",
		FilePath: defaultCSVName(name),
	}
	ok, err := dlg.ShowSave(a.mw)
	if err != nil {
		a.showError("导出失败", err)
		return
	}
	if !ok {
		return
	}
	path := ensureCSVExt(dlg.FilePath)
	if err := writeCSVFile(path, model.Headers(), model.Rows()); err != nil {
		a.showError("导出失败", err)
		return
	}
	a.setStatus("已导出：" + path)
}

func (a *legacyApp) setStatus(text string) {
	if a.status == nil {
		return
	}
	_ = a.status.SetText(time.Now().Format("15:04:05") + "  " + text)
}

func (a *legacyApp) setSummary(label *walk.Label, text string) {
	if label == nil {
		return
	}
	_ = label.SetText(text)
}

func (a *legacyApp) showError(title string, err error) {
	if err == nil {
		return
	}
	walk.MsgBox(a.mw, title, err.Error(), walk.MsgBoxIconError)
}

func toTableViewColumns(columns []tableColumn) []TableViewColumn {
	out := make([]TableViewColumn, len(columns))
	for i, col := range columns {
		out[i] = TableViewColumn{Title: col.Title, Width: col.Width}
	}
	return out
}

func processRows(items []process.Info) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.PID), 10),
			item.Name,
			item.CPUPercent,
			formatMB(item.WorkingSetKB),
			strconv.FormatUint(uint64(item.ThreadCount), 10),
			strconv.FormatUint(uint64(item.HandleCount), 10),
			strconv.Itoa(item.ConnectionCount),
			item.MD5,
			item.Signature,
			strconv.FormatUint(uint64(item.ParentPID), 10),
			item.ParentName,
			item.CreatedAt,
			item.Path,
			item.CommandLine,
			strings.TrimSpace(item.HashError + " " + item.PathError),
		})
	}
	return rows
}

func processSummaryText(items []process.Info) string {
	connected := 0
	unsigned := 0
	pathErrors := 0
	highConnections := 0
	highMemory := 0
	maxCPU := 0.0
	for _, item := range items {
		if item.ConnectionCount > 0 {
			connected++
		}
		if item.ConnectionCount >= 20 {
			highConnections++
		}
		if isUnsignedSignature(item.Signature) {
			unsigned++
		}
		if strings.TrimSpace(item.HashError+item.PathError) != "" {
			pathErrors++
		}
		if item.WorkingSetKB >= 512*1024 {
			highMemory++
		}
		if cpu, err := strconv.ParseFloat(item.CPUPercent, 64); err == nil && cpu > maxCPU {
			maxCPU = cpu
		}
	}
	return fmt.Sprintf("进程 %d    联网进程 %d    无签名 %d    高连接数 %d    内存>=512MB %d    最高CPU %.1f%%    文件访问/MD5 异常 %d",
		len(items), connected, unsigned, highConnections, highMemory, maxCPU, pathErrors)
}

func moduleRows(items []process.ModuleInfo) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Name,
			item.MD5,
			item.Signature,
			item.BaseAddress,
			strconv.FormatUint(uint64(item.SizeKB), 10),
			item.Path,
			item.HashError,
		})
	}
	return rows
}

func connectionRows(items []process.ConnectionInfo) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Protocol,
			item.RemoteKind,
			item.Local,
			item.Remote,
			item.State,
			strconv.FormatUint(uint64(item.LocalPort), 10),
			strconv.FormatUint(uint64(item.RemotePort), 10),
		})
	}
	return rows
}

func processDetailSummary(pid uint32, name string, modules []process.ModuleInfo, connections []process.ConnectionInfo, moduleErr, connectionErr error) string {
	external := 0
	for _, conn := range connections {
		if conn.RemoteKind == "公网/外部" {
			external++
		}
	}
	parts := []string{
		fmt.Sprintf("%s (PID %d)", name, pid),
		fmt.Sprintf("模块 %d", len(modules)),
		fmt.Sprintf("连接 %d", len(connections)),
		fmt.Sprintf("公网连接 %d", external),
	}
	if moduleErr != nil {
		parts = append(parts, "模块读取失败: "+moduleErr.Error())
	}
	if connectionErr != nil {
		parts = append(parts, "连接读取失败: "+connectionErr.Error())
	}
	return strings.Join(parts, "    ")
}

func hostSummaryText(snapshot host.Snapshot) string {
	unsigned := 0
	for _, item := range snapshot.Services {
		if isUnsignedSignature(item.Signature) {
			unsigned++
		}
	}
	for _, item := range snapshot.ScheduledTasks {
		if isUnsignedSignature(item.Signature) {
			unsigned++
		}
	}
	for _, item := range snapshot.StartupItems {
		if isUnsignedSignature(item.Signature) {
			unsigned++
		}
	}
	for _, item := range snapshot.ImageHijacks {
		if isUnsignedSignature(item.Signature) {
			unsigned++
		}
	}
	for _, item := range snapshot.PersistenceItems {
		if isUnsignedSignature(item.Signature) {
			unsigned++
		}
	}
	return fmt.Sprintf("服务 %d    计划任务 %d    启动项 %d    用户 %d    镜像劫持 %d    持久化 %d    无签名 %d    采集提示 %d",
		len(snapshot.Services), len(snapshot.ScheduledTasks), len(snapshot.StartupItems), len(snapshot.Users), len(snapshot.ImageHijacks), len(snapshot.PersistenceItems), unsigned, len(snapshot.CollectionErrors))
}

func findingSummaryText(items []analysis.Finding) string {
	high := 0
	medium := 0
	low := 0
	for _, item := range items {
		switch item.Level {
		case "高":
			high++
		case "中":
			medium++
		case "低":
			low++
		}
	}
	return fmt.Sprintf("关注项 %d    高 %d    中 %d    低 %d", len(items), high, medium, low)
}

func eventSummaryText(events []securitylog.Event, warnings []string) string {
	logon := 0
	failed := 0
	rdp := 0
	services := 0
	for _, item := range events {
		if strings.Contains(item.Action, "登录成功") {
			logon++
		}
		if strings.Contains(item.Action, "登录失败") {
			failed++
		}
		if strings.Contains(item.LogonTypeName, "RDP") || strings.Contains(item.Action, "RDP") {
			rdp++
		}
		if strings.Contains(item.Action, "服务") {
			services++
		}
	}
	return fmt.Sprintf("事件 %d    登录成功 %d    登录失败 %d    RDP %d    服务相关 %d    采集提示 %d",
		len(events), logon, failed, rdp, services, len(warnings))
}

func historySummaryText(records []history.Record, warnings []string) string {
	sysmon := 0
	dns := 0
	wfp := 0
	firewall := 0
	cache := 0
	for _, item := range records {
		switch {
		case strings.Contains(item.Source, "Sysmon"):
			sysmon++
		case strings.Contains(item.Source, "DNS Client"):
			dns++
		case strings.Contains(item.Source, "WFP"):
			wfp++
		case strings.Contains(item.Source, "防火墙"):
			firewall++
		case strings.Contains(item.Source, "DNS 缓存"):
			cache++
		}
	}
	return fmt.Sprintf("记录 %d    Sysmon %d    DNS Client %d    WFP %d    防火墙 %d    DNS缓存 %d    采集提示 %d",
		len(records), sysmon, dns, wfp, firewall, cache, len(warnings))
}

func fileTraceSummaryText(records []filetrace.Record, warnings []string) string {
	temp := 0
	modified := 0
	recentRun := 0
	high := 0
	medium := 0
	for _, item := range records {
		switch item.Category {
		case "Temp 临时文件":
			temp++
		case "最近修改文件":
			modified++
		case "最近运行文件":
			recentRun++
		}
		switch item.Suspicion {
		case "高":
			high++
		case "中":
			medium++
		}
	}
	return fmt.Sprintf("文件痕迹 %d    Temp %d    最近修改 %d    最近运行 %d    高可疑 %d    中可疑 %d    采集提示 %d",
		len(records), temp, modified, recentRun, high, medium, len(warnings))
}

func aiSummaryText(resp aianalysis.AnalyzeResponse) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%s / %s", resp.Provider, resp.Model))
	if resp.Usage.TotalTokens > 0 {
		parts = append(parts, fmt.Sprintf("Token %d", resp.Usage.TotalTokens))
	}
	if resp.PromptBytes > 0 {
		parts = append(parts, fmt.Sprintf("提示 %.1fKB", float64(resp.PromptBytes)/1024))
	}
	if len(resp.CollectionErrors) > 0 {
		parts = append(parts, fmt.Sprintf("采集提示 %d 条", len(resp.CollectionErrors)))
	}
	if resp.GeneratedAt != "" {
		parts = append(parts, resp.GeneratedAt)
	}
	return strings.Join(parts, "    ")
}

func isUnsignedSignature(value string) bool {
	return strings.Contains(value, "无签名")
}

func serviceRows(items []host.ServiceInfo) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Name, item.DisplayName, item.State, item.StartMode, item.Account,
			item.MD5, item.Signature, item.Path, item.Command, item.HashError,
		})
	}
	return rows
}

func taskRows(items []host.ScheduledTaskInfo) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Name, item.Path, item.State, item.Status, item.Author,
			item.MD5, item.Signature, item.Executable, item.Command, item.Arguments, item.HashError,
		})
	}
	return rows
}

func startupRows(items []host.StartupItem) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Source, item.Name, item.MD5, item.Signature, item.Path, item.Command, item.Location, item.HashError,
		})
	}
	return rows
}

func userRows(items []host.UserInfo) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Name,
			item.SID,
			formatBool(item.Disabled),
			formatBool(item.Lockout),
			formatBool(item.PasswordRequired),
			formatBool(item.LocalAccount),
		})
	}
	return rows
}

func ifeoRows(items []host.ImageHijackInfo) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Image, item.MD5, item.Signature, item.Path, item.Debugger, item.RegistryPath, item.HashError,
		})
	}
	return rows
}

func persistenceRows(items []host.PersistenceInfo) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Category,
			item.Name,
			eventDisplayText(item.Value),
			item.Location,
			item.MD5,
			item.Signature,
			item.Path,
			item.HashError,
		})
	}
	return rows
}

func hostRowsFromServices(items [][]string) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			"服务",
			displayNameAt(item, 0, 1),
			joinParts(valueAt(item, 2), valueAt(item, 3)),
			valueAt(item, 4),
			valueAt(item, 5),
			valueAt(item, 6),
			valueAt(item, 7),
			valueAt(item, 8),
			"",
			valueAt(item, 9),
		})
	}
	return rows
}

func hostRowsFromTasks(items [][]string) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			"计划任务",
			displayNameAt(item, 0, 1),
			joinParts(valueAt(item, 2), valueAt(item, 3)),
			valueAt(item, 4),
			valueAt(item, 5),
			valueAt(item, 6),
			valueAt(item, 7),
			joinParts(valueAt(item, 8), valueAt(item, 9)),
			valueAt(item, 1),
			valueAt(item, 10),
		})
	}
	return rows
}

func hostRowsFromStartup(items [][]string) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			"启动项",
			valueAt(item, 1),
			valueAt(item, 0),
			"",
			valueAt(item, 2),
			valueAt(item, 3),
			valueAt(item, 4),
			valueAt(item, 5),
			valueAt(item, 6),
			valueAt(item, 7),
		})
	}
	return rows
}

func hostRowsFromUsers(items [][]string) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		status := fmt.Sprintf("禁用:%s  锁定:%s  需要密码:%s  本地账户:%s", valueAt(item, 2), valueAt(item, 3), valueAt(item, 4), valueAt(item, 5))
		rows = append(rows, []string{
			"用户",
			valueAt(item, 0),
			status,
			valueAt(item, 1),
			"",
			"",
			"",
			"",
			"",
			"",
		})
	}
	return rows
}

func hostRowsFromIFEO(items [][]string) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			"镜像劫持",
			valueAt(item, 0),
			"",
			"",
			valueAt(item, 1),
			valueAt(item, 2),
			valueAt(item, 3),
			valueAt(item, 4),
			valueAt(item, 5),
			valueAt(item, 6),
		})
	}
	return rows
}

func hostRowsFromPersistence(items [][]string) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			"持久化",
			displayNameAt(item, 0, 1),
			valueAt(item, 0),
			"",
			valueAt(item, 4),
			valueAt(item, 5),
			valueAt(item, 6),
			valueAt(item, 2),
			valueAt(item, 3),
			valueAt(item, 7),
		})
	}
	return rows
}

func findingRows(items []analysis.Finding) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Level,
			item.Source,
			item.Name,
			item.Reason,
			item.MD5,
			item.Signature,
			item.Path,
			item.Command,
			item.Extra,
		})
	}
	return rows
}

func eventRows(items []securitylog.Event) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		command := eventDisplayText(item.Command)
		details := eventDisplayText(item.Details)
		if details == "" {
			details = eventDisplayText(item.Message)
		}
		rows = append(rows, []string{
			item.Time,
			item.Category,
			item.Action,
			item.EventID,
			displayAccount(item.Domain, item.Account),
			item.SourceIP,
			item.LogonTypeName,
			item.Process,
			item.ServiceName,
			command,
			details,
		})
	}
	return rows
}

func eventWarningRows(generatedAt string, warnings []string) [][]string {
	rows := make([][]string, 0, len(warnings))
	if generatedAt == "" {
		generatedAt = time.Now().Format("2006-01-02 15:04:05")
	}
	for _, warning := range warnings {
		rows = append(rows, []string{
			generatedAt,
			"采集提示",
			warning,
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			warning,
		})
	}
	return rows
}

func historyRows(items []history.Record) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Time,
			item.Source,
			item.EventID,
			item.Process,
			item.PID,
			item.Proto,
			item.Local,
			item.Remote,
			item.Query,
			item.Action,
			item.User,
			eventDisplayText(item.Details),
		})
	}
	return rows
}

func historyWarningRows(generatedAt string, warnings []string) [][]string {
	rows := make([][]string, 0, len(warnings))
	if generatedAt == "" {
		generatedAt = time.Now().Format("2006-01-02 15:04:05")
	}
	for _, warning := range warnings {
		rows = append(rows, []string{generatedAt, "采集提示", "", "", "", "", "", "", "", warning, "", warning})
	}
	return rows
}

func fileTraceRows(items []filetrace.Record) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Category,
			item.Source,
			item.Name,
			item.Suspicion,
			item.Reason,
			item.Modified,
			item.LastRun,
			item.RunCount,
			formatKB(item.Size),
			item.Extension,
			item.Path,
			fileTraceDetails(item),
		})
	}
	return rows
}

func fileTraceWarningRows(generatedAt string, warnings []string) [][]string {
	rows := make([][]string, 0, len(warnings))
	if generatedAt == "" {
		generatedAt = time.Now().Format("2006-01-02 15:04:05")
	}
	for _, warning := range warnings {
		rows = append(rows, []string{"采集提示", "系统", warning, "", warning, generatedAt, "", "", "", "", "", warning})
	}
	return rows
}

func fileTraceDetails(item filetrace.Record) string {
	var parts []string
	if strings.TrimSpace(item.Directory) != "" {
		parts = append(parts, "目录: "+item.Directory)
	}
	if strings.TrimSpace(item.Created) != "" {
		parts = append(parts, "创建: "+item.Created)
	}
	if strings.TrimSpace(item.Accessed) != "" {
		parts = append(parts, "访问: "+item.Accessed)
	}
	if strings.TrimSpace(item.Details) != "" {
		parts = append(parts, item.Details)
	}
	return strings.Join(parts, " / ")
}

func displayAccount(domain, account string) string {
	if strings.TrimSpace(domain) == "" {
		return account
	}
	if strings.TrimSpace(account) == "" {
		return domain
	}
	return domain + `\` + account
}

func formatBool(value bool) string {
	if value {
		return "是"
	}
	return "否"
}

func filterRows(rows [][]string, q string) [][]string {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return copyRows(rows)
	}
	filtered := make([][]string, 0, len(rows))
	for _, row := range rows {
		for _, value := range row {
			if strings.Contains(strings.ToLower(value), q) {
				filtered = append(filtered, append([]string(nil), row...))
				break
			}
		}
	}
	return filtered
}

func copyRows(rows [][]string) [][]string {
	out := make([][]string, len(rows))
	for i := range rows {
		out[i] = append([]string(nil), rows[i]...)
	}
	return out
}

func appendRows(dst [][]string, src [][]string) [][]string {
	for _, row := range src {
		dst = append(dst, append([]string(nil), row...))
	}
	return dst
}

func lineText(edit *walk.LineEdit) string {
	if edit == nil {
		return ""
	}
	return strings.TrimSpace(edit.Text())
}

func textEditText(edit *walk.TextEdit) string {
	if edit == nil {
		return ""
	}
	return strings.TrimSpace(edit.Text())
}

func comboText(combo *walk.ComboBox) string {
	if combo == nil {
		return ""
	}
	return strings.TrimSpace(combo.Text())
}

func checkBoxChecked(box *walk.CheckBox) bool {
	return box != nil && box.Checked()
}

func splitPathList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ';' || r == '\n' || r == '\r' || r == '|'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func currentTableRow(view *walk.TableView, model *tableModel) []string {
	if view == nil || model == nil {
		return nil
	}
	index := view.CurrentIndex()
	if index < 0 || index >= len(model.rows) {
		return nil
	}
	return model.rows[index]
}

func valueAt(row []string, index int) string {
	if index < 0 || index >= len(row) {
		return ""
	}
	return row[index]
}

func compactStatusValue(value string) string {
	value = strings.TrimSpace(value)
	if len([]rune(value)) <= 96 {
		return value
	}
	runes := []rune(value)
	return string(runes[:46]) + "..." + string(runes[len(runes)-46:])
}

func eventDisplayText(value string) string {
	return limitRunes(strings.Join(strings.Fields(value), " "), 360)
}

func limitRunes(value string, max int) string {
	value = strings.TrimSpace(value)
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

func formatMB(kb uint64) string {
	if kb == 0 {
		return "0"
	}
	return fmt.Sprintf("%.1f", float64(kb)/1024)
}

func formatKB(bytes int64) string {
	if bytes <= 0 {
		return "0"
	}
	return fmt.Sprintf("%.1f", float64(bytes)/1024)
}

func displayNameAt(row []string, primaryIndex, secondaryIndex int) string {
	primary := valueAt(row, primaryIndex)
	secondary := valueAt(row, secondaryIndex)
	if secondary == "" || secondary == primary {
		return primary
	}
	if primary == "" {
		return secondary
	}
	return primary + " / " + secondary
}

func joinParts(values ...string) string {
	var parts []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, " / ")
}

func aiModelOptions() []string {
	return []string{
		"gpt-5.5",
		"gpt-5.5-mini",
		"gpt-5.4-mini",
		"gpt-5.4-nano",
		"gpt-5.4",
		"deepseek-v4-flash",
		"deepseek-v4-pro",
		"deepseek-chat",
		"deepseek-reasoner",
		"kimi-k2.6",
		"kimi-k2.5",
		"kimi-k2",
		"kimi-latest",
		"moonshot-v1-8k",
		"qwen3.7-plus",
		"qwen3.7-max",
		"qwen-plus",
		"qwen-max",
		"qwen-turbo",
	}
}

func aiProviderValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "deepseek":
		return "deepseek"
	case "kimi", "moonshot":
		return "kimi"
	case "qwen", "dashscope":
		return "qwen"
	case "custom", "自定义":
		return "custom"
	default:
		return "openai"
	}
}

func defaultAIModel(provider string) string {
	switch provider {
	case "deepseek":
		return "deepseek-v4-flash"
	case "kimi":
		return "kimi-k2.6"
	case "qwen":
		return "qwen3.7-plus"
	case "custom":
		return "model-name"
	default:
		return "gpt-5.5"
	}
}

func defaultAIBaseURL(provider string) string {
	switch provider {
	case "deepseek":
		return "https://api.deepseek.com"
	case "kimi":
		return "https://api.moonshot.ai/v1"
	case "qwen":
		return "https://dashscope.aliyuncs.com/compatible-mode/v1"
	case "custom":
		return ""
	default:
		return "https://api.openai.com/v1"
	}
}

func renderAITranscript(messages []aianalysis.Message, resp aianalysis.AnalyzeResponse) string {
	var lines []string
	lines = append(lines, "WinTraceLens Legacy AI 分析")
	lines = append(lines, "时间: "+resp.GeneratedAt)
	lines = append(lines, "模型: "+strings.TrimSpace(resp.Provider+" / "+resp.Model))
	if resp.Endpoint != "" {
		lines = append(lines, "接口: "+resp.Endpoint)
	}
	if resp.Usage.TotalTokens > 0 {
		lines = append(lines, fmt.Sprintf("Token: prompt=%d completion=%d total=%d", resp.Usage.PromptTokens, resp.Usage.CompletionTokens, resp.Usage.TotalTokens))
	}
	if len(resp.Sections) > 0 {
		var summaries []string
		for _, section := range resp.Sections {
			if section.Error != "" {
				summaries = append(summaries, fmt.Sprintf("%s=错误", section.Label))
			} else {
				summaries = append(summaries, fmt.Sprintf("%s=%d", section.Label, section.Count))
			}
		}
		lines = append(lines, "证据: "+strings.Join(summaries, "  "))
	}
	if len(resp.CollectionErrors) > 0 {
		lines = append(lines, "采集提示:")
		for _, item := range resp.CollectionErrors {
			lines = append(lines, "- "+item)
		}
	}
	lines = append(lines, "")
	for _, message := range messages {
		role := "用户"
		if strings.EqualFold(message.Role, "assistant") {
			role = "AI"
		}
		lines = append(lines, "==== "+role+" ====")
		lines = append(lines, strings.TrimSpace(message.Content))
		lines = append(lines, "")
	}
	return strings.Join(lines, "\r\n")
}

func currentIndex(tabs *walk.TabWidget) int {
	if tabs == nil {
		return -1
	}
	return tabs.CurrentIndex()
}

func naturalLess(a, b string) bool {
	af, aerr := strconv.ParseFloat(strings.TrimSpace(a), 64)
	bf, berr := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if aerr == nil && berr == nil {
		return af < bf
	}
	return strings.ToLower(a) < strings.ToLower(b)
}

func eventRowMatchesCategory(row []string, category string) bool {
	eventID := valueAt(row, 3)
	action := valueAt(row, 2)
	rowCategory := valueAt(row, 1)
	logonType := valueAt(row, 6)
	switch category {
	case "logon-success":
		return eventID == "4624"
	case "logon-failed":
		return eventID == "4625"
	case "rdp":
		return strings.Contains(rowCategory, "RDP") || strings.Contains(action, "RDP") || strings.Contains(logonType, "RDP") ||
			eventID == "1149" || eventID == "21" || eventID == "22" || eventID == "23" || eventID == "24" || eventID == "25" || eventID == "39" || eventID == "40"
	case "service":
		return eventID == "7045"
	case "user-create":
		return eventID == "4720"
	case "powershell":
		return strings.Contains(rowCategory, "PowerShell")
	default:
		return true
	}
}

func eventCategoryName(category string) string {
	switch category {
	case "logon-success":
		return "登录成功"
	case "logon-failed":
		return "登录失败"
	case "rdp":
		return "RDP"
	case "service":
		return "服务创建"
	case "user-create":
		return "用户创建"
	case "powershell":
		return "PowerShell"
	default:
		return "全部"
	}
}

func defaultCSVName(name string) string {
	return fmt.Sprintf("%s-%s.csv", name, time.Now().Format("20060102-150405"))
}

func defaultPackageName() string {
	return fmt.Sprintf("WinTraceLens-legacy-evidence-%s.zip", time.Now().Format("20060102-150405"))
}

func ensureCSVExt(path string) string {
	if strings.EqualFold(filepath.Ext(path), ".csv") {
		return path
	}
	return path + ".csv"
}

func ensureZIPExt(path string) string {
	if strings.EqualFold(filepath.Ext(path), ".zip") {
		return path
	}
	return path + ".zip"
}

func headersOf(columns []tableColumn) []string {
	headers := make([]string, len(columns))
	for i, column := range columns {
		headers[i] = column.Title
	}
	return headers
}

func warningRows(items []string) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{item})
	}
	return rows
}

func evidenceSummary(generatedAt string, processes []process.Info, hostSnapshot host.Snapshot, findings []analysis.Finding, securitySnapshot securitylog.Snapshot, historySnapshot history.Snapshot, fileTraceSnapshot filetrace.Snapshot, procErr, hostErr, eventErr, historyErr, fileTraceErr, connectionErr, moduleErr error) string {
	lines := []string{
		"WinTraceLens Legacy 取证包",
		"生成时间: " + generatedAt,
		"版本: " + version,
		"",
		processSummaryText(processes),
		hostSummaryText(hostSnapshot),
		findingSummaryText(findings),
		eventSummaryText(securitySnapshot.Events, securitySnapshot.CollectionErrors),
		historySummaryText(historySnapshot.Records, historySnapshot.CollectionErrors),
		fileTraceSummaryText(fileTraceSnapshot.Records, fileTraceSnapshot.CollectionErrors),
		"",
		"文件清单:",
		"- processes.csv",
		"- process-modules.csv（最多 80 个进程，优先联网和异常进程）",
		"- network-connections.csv",
		"- network-history.csv",
		"- file-traces.csv",
		"- host-all.csv / host-services.csv / host-tasks.csv / host-startup.csv / host-users.csv / host-ifeo.csv / host-persistence.csv",
		"- findings.csv",
		"- security-events.csv",
		"- collection-warnings.csv（仅在存在采集提示时生成）",
	}
	var errs []string
	if procErr != nil {
		errs = append(errs, "进程采集失败: "+procErr.Error())
	}
	if hostErr != nil {
		errs = append(errs, "主机信息采集失败: "+hostErr.Error())
	}
	if eventErr != nil {
		errs = append(errs, "事件日志采集失败: "+eventErr.Error())
	}
	if historyErr != nil {
		errs = append(errs, "历史通信采集失败: "+historyErr.Error())
	}
	if fileTraceErr != nil {
		errs = append(errs, "文件痕迹采集失败: "+fileTraceErr.Error())
	}
	if connectionErr != nil {
		errs = append(errs, "实时连接采集失败: "+connectionErr.Error())
	}
	if moduleErr != nil {
		errs = append(errs, "模块采集提示: "+moduleErr.Error())
	}
	errs = append(errs, hostSnapshot.CollectionErrors...)
	errs = append(errs, securitySnapshot.CollectionErrors...)
	errs = append(errs, historySnapshot.CollectionErrors...)
	errs = append(errs, fileTraceSnapshot.CollectionErrors...)
	if len(errs) > 0 {
		lines = append(lines, "", "采集提示:")
		for _, err := range errs {
			lines = append(lines, "- "+err)
		}
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

func writeCSVFile(path string, headers []string, rows [][]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	writer.UseCRLF = true
	if err := writer.Write(sanitizeCSVRow(headers)); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writer.Write(sanitizeCSVRow(row)); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func packageFileTraceOptions(eventOpts securitylog.Options) filetrace.Options {
	hours := 24 * 7
	if !eventOpts.StartTime.IsZero() {
		span := time.Since(eventOpts.StartTime)
		if span > 0 {
			hours = int(span.Hours()) + 24
		}
	}
	maxRecords := eventOpts.MaxRecords
	if maxRecords <= 0 {
		maxRecords = 500
	}
	return filetrace.Options{Hours: hours, MaxRecords: maxRecords}
}

func writeEvidencePackage(path string, eventOpts securitylog.Options, hashLimitBytes int64) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	zw := zip.NewWriter(file)
	defer zw.Close()

	generatedAt := time.Now().Format("2006-01-02 15:04:05")
	processes, procErr := process.Collect(process.Options{HashLimitBytes: hashLimitBytes})
	hostSnapshot, hostErr := host.Collect(host.Options{HashLimitBytes: hashLimitBytes})
	securitySnapshot, eventErr := securitylog.Collect(eventOpts)
	historySnapshot, historyErr := history.Collect(history.Options{StartTime: eventOpts.StartTime, EndTime: eventOpts.EndTime, MaxRecords: eventOpts.MaxRecords})
	fileTraceSnapshot, fileTraceErr := filetrace.Collect(packageFileTraceOptions(eventOpts))
	connections, connectionErr := process.CollectConnections()
	moduleRows, moduleErr := packageModuleRows(processes, hashLimitBytes)
	findings := analysis.BuildFindings(processes, hostSnapshot)

	if err := writeZipText(zw, "summary.txt", evidenceSummary(generatedAt, processes, hostSnapshot, findings, securitySnapshot, historySnapshot, fileTraceSnapshot, procErr, hostErr, eventErr, historyErr, fileTraceErr, connectionErr, moduleErr)); err != nil {
		return err
	}
	if procErr == nil {
		if err := writeZipCSV(zw, "processes.csv", headersOf(processColumns), processRows(processes)); err != nil {
			return err
		}
	}
	if connectionErr == nil {
		if err := writeZipCSV(zw, "network-connections.csv", []string{"PID", "协议", "远程类型", "本地地址", "远程地址", "状态", "本地端口", "远程端口"}, packageConnectionRows(connections)); err != nil {
			return err
		}
	}
	if len(moduleRows) > 0 {
		if err := writeZipCSV(zw, "process-modules.csv", []string{"PID", "进程", "模块", "MD5", "签名", "基址", "大小KB", "路径", "错误"}, moduleRows); err != nil {
			return err
		}
	}
	if hostErr == nil {
		serviceRows := serviceRows(hostSnapshot.Services)
		taskRows := taskRows(hostSnapshot.ScheduledTasks)
		startupRows := startupRows(hostSnapshot.StartupItems)
		userRows := userRows(hostSnapshot.Users)
		ifeoRows := ifeoRows(hostSnapshot.ImageHijacks)
		persistenceRows := persistenceRows(hostSnapshot.PersistenceItems)
		allRows := appendRows(nil, hostRowsFromServices(serviceRows))
		allRows = appendRows(allRows, hostRowsFromTasks(taskRows))
		allRows = appendRows(allRows, hostRowsFromStartup(startupRows))
		allRows = appendRows(allRows, hostRowsFromUsers(userRows))
		allRows = appendRows(allRows, hostRowsFromIFEO(ifeoRows))
		allRows = appendRows(allRows, hostRowsFromPersistence(persistenceRows))
		if err := writeZipCSV(zw, "host-all.csv", headersOf(hostColumns), allRows); err != nil {
			return err
		}
		if err := writeZipCSV(zw, "host-services.csv", headersOf(serviceColumns), serviceRows); err != nil {
			return err
		}
		if err := writeZipCSV(zw, "host-tasks.csv", headersOf(taskColumns), taskRows); err != nil {
			return err
		}
		if err := writeZipCSV(zw, "host-startup.csv", headersOf(startupColumns), startupRows); err != nil {
			return err
		}
		if err := writeZipCSV(zw, "host-users.csv", headersOf(userColumns), userRows); err != nil {
			return err
		}
		if err := writeZipCSV(zw, "host-ifeo.csv", headersOf(ifeoColumns), ifeoRows); err != nil {
			return err
		}
		if err := writeZipCSV(zw, "host-persistence.csv", headersOf(persistenceColumns), persistenceRows); err != nil {
			return err
		}
	}
	if err := writeZipCSV(zw, "findings.csv", headersOf(findingColumns), findingRows(findings)); err != nil {
		return err
	}
	if eventErr == nil {
		rows := eventRows(securitySnapshot.Events)
		rows = append(rows, eventWarningRows(securitySnapshot.GeneratedAt, securitySnapshot.CollectionErrors)...)
		if err := writeZipCSV(zw, "security-events.csv", headersOf(eventColumns), rows); err != nil {
			return err
		}
	}
	if historyErr == nil {
		rows := historyRows(historySnapshot.Records)
		rows = appendRows(rows, historyWarningRows(historySnapshot.GeneratedAt, historySnapshot.CollectionErrors))
		if err := writeZipCSV(zw, "network-history.csv", headersOf(historyColumns), rows); err != nil {
			return err
		}
	}
	if fileTraceErr == nil {
		rows := fileTraceRows(fileTraceSnapshot.Records)
		rows = appendRows(rows, fileTraceWarningRows(fileTraceSnapshot.GeneratedAt, fileTraceSnapshot.CollectionErrors))
		if err := writeZipCSV(zw, "file-traces.csv", headersOf(fileTraceColumns), rows); err != nil {
			return err
		}
	}
	var errs []string
	if procErr != nil {
		errs = append(errs, "进程采集失败: "+procErr.Error())
	}
	if hostErr != nil {
		errs = append(errs, "主机信息采集失败: "+hostErr.Error())
	}
	if eventErr != nil {
		errs = append(errs, "事件日志采集失败: "+eventErr.Error())
	}
	if historyErr != nil {
		errs = append(errs, "历史通信采集失败: "+historyErr.Error())
	}
	if fileTraceErr != nil {
		errs = append(errs, "文件痕迹采集失败: "+fileTraceErr.Error())
	}
	if connectionErr != nil {
		errs = append(errs, "实时连接采集失败: "+connectionErr.Error())
	}
	if moduleErr != nil {
		errs = append(errs, "模块采集提示: "+moduleErr.Error())
	}
	errs = append(errs, hostSnapshot.CollectionErrors...)
	errs = append(errs, securitySnapshot.CollectionErrors...)
	errs = append(errs, historySnapshot.CollectionErrors...)
	errs = append(errs, fileTraceSnapshot.CollectionErrors...)
	if len(errs) > 0 {
		if err := writeZipCSV(zw, "collection-warnings.csv", []string{"提示"}, warningRows(errs)); err != nil {
			return err
		}
	}
	return nil
}

func writeZipCSV(zw *zip.Writer, name string, headers []string, rows [][]string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	writer := csv.NewWriter(w)
	writer.UseCRLF = true
	if err := writer.Write(sanitizeCSVRow(headers)); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writer.Write(sanitizeCSVRow(row)); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func writeZipText(zw *zip.Writer, name, text string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(text))
	return err
}

func packageConnectionRows(items []process.ConnectionInfo) [][]string {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(item.PID), 10),
			item.Protocol,
			item.RemoteKind,
			item.Local,
			item.Remote,
			item.State,
			strconv.FormatUint(uint64(item.LocalPort), 10),
			strconv.FormatUint(uint64(item.RemotePort), 10),
		})
	}
	return rows
}

func packageModuleRows(items []process.Info, hashLimitBytes int64) ([][]string, error) {
	selected := packageModuleTargets(items, 80)
	rows := make([][]string, 0)
	var errors []string
	for _, procInfo := range selected {
		modules, err := process.Modules(procInfo.PID, process.Options{HashLimitBytes: hashLimitBytes})
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s(PID %d): %s", procInfo.Name, procInfo.PID, err.Error()))
			rows = append(rows, []string{
				strconv.FormatUint(uint64(procInfo.PID), 10),
				procInfo.Name,
				"",
				"",
				"",
				"",
				"",
				"",
				err.Error(),
			})
			continue
		}
		for _, module := range modules {
			rows = append(rows, []string{
				strconv.FormatUint(uint64(procInfo.PID), 10),
				procInfo.Name,
				module.Name,
				module.MD5,
				module.Signature,
				module.BaseAddress,
				strconv.FormatUint(uint64(module.SizeKB), 10),
				module.Path,
				module.HashError,
			})
		}
	}
	if len(errors) > 0 {
		return rows, fmt.Errorf("部分进程模块读取失败 %d 条", len(errors))
	}
	return rows, nil
}

func packageModuleTargets(items []process.Info, limit int) []process.Info {
	if limit <= 0 || len(items) <= limit {
		return append([]process.Info(nil), items...)
	}
	selected := make([]process.Info, 0, limit)
	seen := make(map[uint32]struct{})
	add := func(item process.Info) {
		if len(selected) >= limit {
			return
		}
		if _, ok := seen[item.PID]; ok {
			return
		}
		seen[item.PID] = struct{}{}
		selected = append(selected, item)
	}
	for _, item := range items {
		if item.ConnectionCount > 0 {
			add(item)
		}
	}
	for _, item := range items {
		if isUnsignedSignature(item.Signature) || strings.TrimSpace(item.PathError+item.HashError) != "" {
			add(item)
		}
	}
	for _, item := range items {
		add(item)
	}
	return selected
}

func sanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, value := range row {
		value = strings.NewReplacer("\x00", " ", "\r", " ", "\n", " ").Replace(value)
		value = strings.Join(strings.Fields(value), " ")
		if value != "" && strings.ContainsAny(value[:1], "=+-@") {
			value = "'" + value
		}
		out[i] = value
	}
	return out
}
