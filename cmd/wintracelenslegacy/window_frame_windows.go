//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/lxn/win"
)

const (
	spiGetHighContrast          = 0x0042
	hcfHighContrastOn           = 0x00000001
	dwmwaWindowCornerPreference = 33
	dwmwaCaptionColor           = 35
	dwmwaTextColor              = 36
	dwmWindowCornerRound        = 2
)

type highContrastInfo struct {
	size          uint32
	flags         uint32
	defaultScheme *uint16
}

var (
	dwmAPI                    = syscall.NewLazyDLL("dwmapi.dll")
	dwmIsCompositionEnabled   = dwmAPI.NewProc("DwmIsCompositionEnabled")
	dwmSetWindowAttribute     = dwmAPI.NewProc("DwmSetWindowAttribute")
	systemParametersInfoWProc = syscall.NewLazyDLL("user32.dll").NewProc("SystemParametersInfoW")
)

func (a *legacyApp) applyWindowFrame() string {
	if a.mw == nil || a.mw.Handle() == 0 {
		return "系统边框"
	}
	if a.forceSystemFrame {
		return "系统边框（命令行强制）"
	}
	if highContrastEnabled() {
		return "系统边框（高对比度模式）"
	}
	if err := dwmAPI.Load(); err != nil {
		return "系统边框（DWM 不可用）"
	}
	var enabled int32
	if result, _, _ := dwmIsCompositionEnabled.Call(uintptr(unsafe.Pointer(&enabled))); result != 0 || enabled == 0 {
		return "系统边框（桌面合成不可用）"
	}

	hwnd := uintptr(a.mw.Handle())
	captionColor := uint32(legacyLight.TitleBar)
	if result, _, _ := dwmSetWindowAttribute.Call(hwnd, dwmwaCaptionColor, uintptr(unsafe.Pointer(&captionColor)), unsafe.Sizeof(captionColor)); result != 0 {
		return fmt.Sprintf("系统边框（标题栏融合不可用: 0x%X）", result)
	}
	textColor := uint32(legacyLight.Text)
	_, _, _ = dwmSetWindowAttribute.Call(hwnd, dwmwaTextColor, uintptr(unsafe.Pointer(&textColor)), unsafe.Sizeof(textColor))
	cornerPreference := uint32(dwmWindowCornerRound)
	_, _, _ = dwmSetWindowAttribute.Call(hwnd, dwmwaWindowCornerPreference, uintptr(unsafe.Pointer(&cornerPreference)), unsafe.Sizeof(cornerPreference))
	win.SetWindowPos(a.mw.Handle(), 0, 0, 0, 0, 0, win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE|win.SWP_FRAMECHANGED)
	return "融合标题栏（保留原生系统行为）"
}

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
