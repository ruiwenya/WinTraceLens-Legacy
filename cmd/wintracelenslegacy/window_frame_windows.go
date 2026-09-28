//go:build windows

package main

import (
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

const (
	spiGetHighContrast  = 0x0042
	hcfHighContrastOn   = 0x00000001
	frameHeightDIP      = 40
	wmReleaseFrameFocus = win.WM_APP + 0x47
)

type highContrastInfo struct {
	size          uint32
	flags         uint32
	defaultScheme *uint16
}

type frameState struct {
	previous uintptr
	app      *legacyApp
}

type ncCalcSizeParams struct {
	rects [3]win.RECT
	pos   *win.WINDOWPOS
}

var (
	systemParametersInfoWProc = syscall.NewLazyDLL("user32.dll").NewProc("SystemParametersInfoW")
	getDoubleClickTimeProc    = syscall.NewLazyDLL("user32.dll").NewProc("GetDoubleClickTime")
	customFrameProcPtr        = syscall.NewCallback(customFrameProc)
	frameMu                   sync.Mutex
	frameWindows              = map[win.HWND]frameState{}
)

func highContrastEnabled() bool {
	info := highContrastInfo{size: uint32(unsafe.Sizeof(highContrastInfo{}))}
	result, _, _ := systemParametersInfoWProc.Call(
		spiGetHighContrast,
		uintptr(info.size),
		uintptr(unsafe.Pointer(&info)),
		0,
	)
	return result != 0 && info.flags&hcfHighContrastOn != 0
}

func (a *legacyApp) applyWindowFrame() string {
	if a.mw == nil || a.mw.Handle() == 0 || !a.integratedFrame {
		return "Windows 系统标题栏"
	}
	hwnd := a.mw.Handle()
	previous := win.SetWindowLongPtr(hwnd, win.GWLP_WNDPROC, customFrameProcPtr)
	if previous == 0 {
		a.fallbackWindowFrame()
		return "Windows 系统标题栏（融合失败）"
	}
	frameMu.Lock()
	frameWindows[hwnd] = frameState{previous: previous, app: a}
	frameMu.Unlock()

	style := win.GetWindowLongPtr(hwnd, win.GWL_STYLE)
	win.SetWindowLongPtr(hwnd, win.GWL_STYLE, style&^uintptr(win.WS_CAPTION))
	if !win.SetWindowPos(hwnd, 0, 0, 0, 0, 0,
		win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE|win.SWP_FRAMECHANGED) {
		frameMu.Lock()
		delete(frameWindows, hwnd)
		frameMu.Unlock()
		win.SetWindowLongPtr(hwnd, win.GWLP_WNDPROC, previous)
		win.SetWindowLongPtr(hwnd, win.GWL_STYLE, style)
		a.fallbackWindowFrame()
		return "Windows 系统标题栏（融合失败）"
	}
	return "融合标题栏"
}

func (a *legacyApp) fallbackWindowFrame() {
	a.integratedFrame = false
	for _, button := range []*walk.PushButton{a.frameMin, a.frameMax, a.frameClose} {
		if button != nil {
			button.SetVisible(false)
		}
	}
}

func (a *legacyApp) beginFrameDrag(x, y int, button walk.MouseButton) {
	if !a.integratedFrame || button != walk.LeftButton || a.mw == nil {
		return
	}
	now := time.Now()
	doubleClickMS, _, _ := getDoubleClickTimeProc.Call()
	if doubleClickMS == 0 {
		doubleClickMS = 500
	}
	threshold := a.mw.IntFrom96DPI(6)
	if !a.frameLastClick.IsZero() && now.Sub(a.frameLastClick) <= time.Duration(doubleClickMS)*time.Millisecond &&
		absInt(x-a.frameLastX) <= threshold && absInt(y-a.frameLastY) <= threshold {
		a.frameLastClick = time.Time{}
		a.toggleWindowMaximize()
		return
	}
	a.frameLastClick, a.frameLastX, a.frameLastY = now, x, y
	win.ReleaseCapture()
	win.SendMessage(a.mw.Handle(), win.WM_NCLBUTTONDOWN, uintptr(win.HTCAPTION), 0)
}

func (a *legacyApp) releaseFrameButtonFocus() {
	if a.mw == nil || a.mw.Handle() == 0 {
		return
	}
	win.PostMessage(a.mw.Handle(), wmReleaseFrameFocus, 0, 0)
}

func (a *legacyApp) frameButtonHasFocus() bool {
	focused := win.GetFocus()
	if focused == 0 {
		return false
	}
	for _, button := range a.frameButtons() {
		if button != nil && button.Handle() == focused {
			return true
		}
	}
	return false
}

func (a *legacyApp) frameButtons() []*walk.PushButton {
	return []*walk.PushButton{
		a.densityToggle, a.frameAbout, a.frameExport,
		a.frameMin, a.frameMax, a.frameClose,
	}
}

func (a *legacyApp) clearFrameButtonDefaultStyles() {
	for _, button := range a.frameButtons() {
		if button != nil && button.Handle() != 0 {
			win.SendMessage(button.Handle(), win.BM_SETSTYLE, uintptr(win.BS_PUSHBUTTON), 1)
		}
	}
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func customFrameProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	frameMu.Lock()
	state, ok := frameWindows[hwnd]
	frameMu.Unlock()
	if !ok {
		return win.DefWindowProc(hwnd, msg, wParam, lParam)
	}

	switch msg {
	case win.WM_ACTIVATE, win.WM_ACTIVATEAPP, win.WM_ENABLE:
		result := win.CallWindowProc(state.previous, hwnd, msg, wParam, lParam)
		if (msg != win.WM_ACTIVATEAPP || wParam != 0) && state.app.frameButtonHasFocus() {
			state.app.releaseFrameButtonFocus()
		}
		if state.app.frameHeader != nil {
			win.InvalidateRect(state.app.frameHeader.Handle(), nil, true)
		}
		return result
	case wmReleaseFrameFocus:
		if state.app.frameHeader != nil && state.app.frameHeader.Handle() != 0 {
			win.SetFocus(state.app.frameHeader.Handle())
		} else {
			win.SetFocus(hwnd)
		}
		state.app.clearFrameButtonDefaultStyles()
		return 0
	case win.WM_NCCALCSIZE:
		if wParam == 0 {
			return win.CallWindowProc(state.previous, hwnd, msg, wParam, lParam)
		}
		params := (*ncCalcSizeParams)(unsafe.Pointer(lParam))
		if win.IsZoomed(hwnd) {
			monitor := win.MonitorFromWindow(hwnd, win.MONITOR_DEFAULTTONEAREST)
			info := win.MONITORINFO{CbSize: uint32(unsafe.Sizeof(win.MONITORINFO{}))}
			if monitor != 0 && win.GetMonitorInfo(monitor, &info) {
				params.rects[0] = info.RcWork
				return 0
			}
		}

		// Let Windows retain its native resize border, then extend only the
		// client top into the old caption area. Painting the entire resize
		// frame as client content causes border remnants after activation.
		top := params.rects[0].Top
		result := win.CallWindowProc(state.previous, hwnd, msg, wParam, lParam)
		params.rects[0].Top = top
		return result
	case win.WM_NCHITTEST:
		if hit := state.app.hitTestIntegratedFrame(hwnd, lParam); hit != 0 {
			return uintptr(hit)
		}
	case win.WM_NCDESTROY:
		frameMu.Lock()
		delete(frameWindows, hwnd)
		frameMu.Unlock()
		win.SetWindowLongPtr(hwnd, win.GWLP_WNDPROC, state.previous)
	}
	return win.CallWindowProc(state.previous, hwnd, msg, wParam, lParam)
}

func (a *legacyApp) hitTestIntegratedFrame(hwnd win.HWND, lParam uintptr) int32 {
	if a.mw == nil {
		return 0
	}
	x := int32(int16(uint16(lParam)))
	y := int32(int16(uint16(lParam >> 16)))
	var rect win.RECT
	if !win.GetWindowRect(hwnd, &rect) {
		return 0
	}

	if !win.IsZoomed(hwnd) {
		border := int32(a.mw.DPI() * 8 / 96)
		if border < 5 {
			border = 5
		}
		left, right := x < rect.Left+border, x >= rect.Right-border
		top, bottom := y < rect.Top+border, y >= rect.Bottom-border
		switch {
		case top && left:
			return win.HTTOPLEFT
		case top && right:
			return win.HTTOPRIGHT
		case bottom && left:
			return win.HTBOTTOMLEFT
		case bottom && right:
			return win.HTBOTTOMRIGHT
		case left:
			return win.HTLEFT
		case right:
			return win.HTRIGHT
		case top:
			return win.HTTOP
		case bottom:
			return win.HTBOTTOM
		}
	}

	headerBottom := rect.Top + int32(a.mw.DPI()*frameHeightDIP/96)
	if y < rect.Top || y >= headerBottom || x < rect.Left || x >= rect.Right {
		return win.HTCLIENT
	}
	for _, button := range a.frameButtons() {
		if button != nil && button.Visible() && frameContains(button.Handle(), x, y) {
			return win.HTCLIENT
		}
	}
	return win.HTCAPTION
}

func frameContains(hwnd win.HWND, x, y int32) bool {
	var rect win.RECT
	return hwnd != 0 && win.GetWindowRect(hwnd, &rect) &&
		x >= rect.Left && x < rect.Right && y >= rect.Top && y < rect.Bottom
}
