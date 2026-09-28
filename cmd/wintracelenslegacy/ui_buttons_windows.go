//go:build windows

package main

import (
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

type buttonRole uint8

const (
	buttonSecondary buttonRole = iota
	buttonPrimary
	buttonLight
)

type styledButton struct {
	previous uintptr
	button   *walk.PushButton
	role     buttonRole
	hover    bool
}

var (
	styledButtonProcPtr = syscall.NewCallback(styledButtonProc)
	fillRectProc        = syscall.NewLazyDLL("user32.dll").NewProc("FillRect")
	styledButtonMu      sync.Mutex
	styledButtons       = map[win.HWND]*styledButton{}
)

func (a *legacyApp) styleToolbarButtons() {
	if a.mw == nil || highContrastEnabled() {
		return
	}
	var visit func(walk.Window)
	visit = func(window walk.Window) {
		if button, ok := window.(*walk.PushButton); ok {
			if button == a.densityToggle || button == a.frameAbout || button == a.frameExport ||
				button == a.frameMin || button == a.frameMax || button == a.frameClose {
				return
			}
			role := buttonSecondary
			text := button.Text()
			switch {
			case text == "恢复窗口", text == "─", text == "□", text == "▣", text == "×":
				role = buttonLight
			case text == "刷新", text == "开始扫描", text == "读取日志", text == "开始分析", text == "采集证据":
				role = buttonPrimary
			}
			applyButtonStyle(button, role)
		}
		if container, ok := window.(walk.Container); ok {
			for i := 0; i < container.Children().Len(); i++ {
				visit(container.Children().At(i))
			}
		}
		if tabs, ok := window.(*walk.TabWidget); ok {
			for i := 0; i < tabs.Pages().Len(); i++ {
				visit(tabs.Pages().At(i))
			}
		}
	}
	visit(a.mw)
}

func applyButtonStyle(button *walk.PushButton, role buttonRole) {
	if button == nil || button.Handle() == 0 {
		return
	}
	hwnd := button.Handle()
	styledButtonMu.Lock()
	if existing := styledButtons[hwnd]; existing != nil {
		existing.role = role
		styledButtonMu.Unlock()
		win.InvalidateRect(hwnd, nil, false)
		return
	}
	styledButtonMu.Unlock()
	previous := win.SetWindowLongPtr(hwnd, win.GWLP_WNDPROC, styledButtonProcPtr)
	if previous == 0 {
		return
	}
	styledButtonMu.Lock()
	styledButtons[hwnd] = &styledButton{previous: previous, button: button, role: role}
	styledButtonMu.Unlock()
	win.InvalidateRect(hwnd, nil, false)
}

func styledButtonProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	styledButtonMu.Lock()
	state := styledButtons[hwnd]
	styledButtonMu.Unlock()
	if state == nil {
		return win.DefWindowProc(hwnd, msg, wParam, lParam)
	}
	if msg == win.WM_NCDESTROY {
		styledButtonMu.Lock()
		delete(styledButtons, hwnd)
		styledButtonMu.Unlock()
		win.SetWindowLongPtr(hwnd, win.GWLP_WNDPROC, state.previous)
		return win.CallWindowProc(state.previous, hwnd, msg, wParam, lParam)
	}
	if highContrastEnabled() {
		return win.CallWindowProc(state.previous, hwnd, msg, wParam, lParam)
	}
	switch msg {
	case win.WM_PAINT:
		drawStyledButton(hwnd, state)
		return 0
	case win.WM_ERASEBKGND:
		return 1
	case win.WM_MOUSEMOVE:
		if !state.hover {
			state.hover = true
			track := win.TRACKMOUSEEVENT{CbSize: uint32(unsafe.Sizeof(win.TRACKMOUSEEVENT{})), DwFlags: win.TME_LEAVE, HwndTrack: hwnd}
			win.TrackMouseEvent(&track)
			win.InvalidateRect(hwnd, nil, false)
		}
	case win.WM_MOUSELEAVE:
		state.hover = false
		win.InvalidateRect(hwnd, nil, false)
	case win.WM_SETFOCUS, win.WM_KILLFOCUS, win.WM_ENABLE, win.WM_LBUTTONDOWN, win.WM_LBUTTONUP:
		defer win.InvalidateRect(hwnd, nil, false)
	}
	return win.CallWindowProc(state.previous, hwnd, msg, wParam, lParam)
}

func drawStyledButton(hwnd win.HWND, state *styledButton) {
	var paint win.PAINTSTRUCT
	hdc := win.BeginPaint(hwnd, &paint)
	if hdc == 0 {
		return
	}
	defer win.EndPaint(hwnd, &paint)
	var rect win.RECT
	if !win.GetClientRect(hwnd, &rect) {
		return
	}
	enabled := win.IsWindowEnabled(hwnd)
	pressed := win.SendMessage(hwnd, win.BM_GETSTATE, 0, 0)&win.BST_PUSHED != 0
	background := legacyLight.Surface
	foreground := legacyLight.Text
	border := legacyLight.Border
	switch state.role {
	case buttonPrimary:
		background, foreground, border = legacyLight.Accent, walk.RGB(255, 255, 255), legacyLight.Accent
		if state.hover {
			background = walk.RGB(29, 78, 180)
		}
		if pressed {
			background = walk.RGB(22, 61, 146)
		}
	case buttonLight:
		background, border = legacyLight.TitleBar, legacyLight.TitleBar
		if state.hover {
			background = legacyLight.Hover
		}
		if pressed {
			background = legacyLight.Selected
		}
	default:
		if state.hover {
			background = legacyLight.Hover
		}
		if pressed {
			background = legacyLight.Selected
		}
	}
	if !enabled {
		background, foreground, border = legacyLight.Chrome, legacyLight.MutedText, legacyLight.Border
	}
	fillButtonRect(hdc, rect, background)
	if state.role != buttonLight || win.GetFocus() == hwnd {
		fillButtonRect(hdc, win.RECT{Left: rect.Left, Top: rect.Top, Right: rect.Right, Bottom: rect.Top + 1}, border)
		fillButtonRect(hdc, win.RECT{Left: rect.Left, Top: rect.Bottom - 1, Right: rect.Right, Bottom: rect.Bottom}, border)
		fillButtonRect(hdc, win.RECT{Left: rect.Left, Top: rect.Top, Right: rect.Left + 1, Bottom: rect.Bottom}, border)
		fillButtonRect(hdc, win.RECT{Left: rect.Right - 1, Top: rect.Top, Right: rect.Right, Bottom: rect.Bottom}, border)
	}
	font := win.SendMessage(hwnd, win.WM_GETFONT, 0, 0)
	if font != 0 {
		previous := win.SelectObject(hdc, win.HGDIOBJ(font))
		defer win.SelectObject(hdc, previous)
	}
	win.SetBkMode(hdc, win.TRANSPARENT)
	win.SetTextColor(hdc, win.COLORREF(foreground))
	text := strings.TrimSpace(state.button.Text())
	ptr, err := syscall.UTF16PtrFromString(text)
	if err == nil {
		textRect := win.RECT{Left: rect.Left + 4, Top: rect.Top + 1, Right: rect.Right - 4, Bottom: rect.Bottom - 1}
		win.DrawTextEx(hdc, ptr, -1, &textRect, win.DT_CENTER|win.DT_VCENTER|win.DT_SINGLELINE|win.DT_END_ELLIPSIS|win.DT_NOPREFIX, nil)
	}
	if win.GetFocus() == hwnd {
		focus := win.RECT{Left: rect.Left + 3, Top: rect.Top + 3, Right: rect.Right - 3, Bottom: rect.Bottom - 3}
		win.DrawFocusRect(hdc, &focus)
	}
}

func fillButtonRect(hdc win.HDC, rect win.RECT, color walk.Color) {
	if rect.Right <= rect.Left || rect.Bottom <= rect.Top {
		return
	}
	brush := win.CreateBrushIndirect(&win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(color)})
	if brush == 0 {
		return
	}
	fillRectProc.Call(uintptr(hdc), uintptr(unsafe.Pointer(&rect)), uintptr(brush))
	win.DeleteObject(win.HGDIOBJ(brush))
}
