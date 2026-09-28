//go:build windows

package main

import (
	"strings"
	"syscall"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

type navigationBar struct {
	widget      *walk.CustomWidget
	labels      []string
	current     int
	focusIndex  int
	hover       int
	pressed     int
	items       []walk.Rectangle
	scrollX     int
	totalWidth  int
	lastWidth   int
	lastDPI     int
	revealFocus bool
	onActivate  func(int)
}

func newNavigationBar(labels []string, onActivate func(int)) *navigationBar {
	return &navigationBar{
		labels:      append([]string(nil), labels...),
		current:     0,
		focusIndex:  0,
		hover:       -1,
		pressed:     -1,
		revealFocus: true,
		onActivate:  onActivate,
	}
}

func (n *navigationBar) widgetSpec(height int) declarative.Widget {
	return declarative.CustomWidget{
		AssignTo:            &n.widget,
		MinSize:             declarative.Size{Height: height},
		MaxSize:             declarative.Size{Height: height},
		StretchFactor:       1,
		Style:               win.WS_TABSTOP,
		PaintMode:           declarative.PaintBuffered,
		InvalidatesOnResize: true,
		PaintPixels:         n.paint,
		OnMouseDown:         n.mouseDown,
		OnMouseMove:         n.mouseMove,
		OnMouseUp:           n.mouseUp,
		OnKeyDown:           n.keyDown,
	}
}

func (n *navigationBar) configure() {
	if n.widget == nil {
		return
	}
	n.updateAccessibleName()
	n.widget.FocusedChanged().Attach(func() {
		_ = n.widget.Invalidate()
	})
	n.widget.MouseLeave().Attach(func() {
		if n.hover == -1 && n.pressed == -1 {
			return
		}
		n.hover = -1
		n.pressed = -1
		_ = n.widget.Invalidate()
	})
}

func (n *navigationBar) setCurrent(index int) {
	if index < 0 || index >= len(n.labels) {
		return
	}
	n.current = index
	n.focusIndex = index
	n.revealFocus = true
	n.updateAccessibleName()
	if n.widget != nil {
		_ = n.widget.Invalidate()
	}
}

func (n *navigationBar) updateAccessibleName() {
	if n.widget == nil || len(n.labels) == 0 {
		return
	}
	_ = n.widget.Accessibility().SetName("功能导航，当前" + n.labels[n.current] + "；" + strings.Join(n.labels, "，"))
}

func navigationRects(widths []int, viewportWidth, scrollX, focusedIndex, controlWidth int) ([]walk.Rectangle, int, int) {
	total := 0
	for _, width := range widths {
		total += width
	}
	visibleWidth := viewportWidth - 2*controlWidth
	if visibleWidth < 1 {
		visibleWidth = 1
	}
	maxScroll := total - visibleWidth
	if maxScroll < 0 {
		maxScroll = 0
	}
	if scrollX > maxScroll {
		scrollX = maxScroll
	}
	if scrollX < 0 {
		scrollX = 0
	}
	if focusedIndex >= 0 && focusedIndex < len(widths) {
		start := 0
		for _, width := range widths[:focusedIndex] {
			start += width
		}
		end := start + widths[focusedIndex]
		if start < scrollX {
			scrollX = start
		} else if end > scrollX+visibleWidth {
			scrollX = end - visibleWidth
		}
		if scrollX > maxScroll {
			scrollX = maxScroll
		}
	}
	items := make([]walk.Rectangle, len(widths))
	left := controlWidth - scrollX
	for i, width := range widths {
		items[i] = walk.Rectangle{X: left, Width: width}
		left += width
	}
	return items, scrollX, total
}

func (n *navigationBar) activate(index int) {
	if index < 0 || index >= len(n.labels) {
		return
	}
	n.setCurrent(index)
	if n.onActivate != nil {
		n.onActivate(index)
	}
}

func (n *navigationBar) itemAt(x, y int) int {
	if n.widget == nil || len(n.labels) == 0 {
		return -1
	}
	return navigationItemAt(n.items, x, y, n.widget.ClientBoundsPixels(), n.overflowWidth())
}

func navigationItemAt(items []walk.Rectangle, x, y int, bounds walk.Rectangle, controlWidth int) int {
	if x < 0 || y < 0 || x >= bounds.Width || y >= bounds.Height {
		return -1
	}
	if controlWidth > 0 && (x < controlWidth || x >= bounds.Width-controlWidth) {
		return -1
	}
	for index, item := range items {
		if x >= item.X && x < item.X+item.Width && y >= item.Y && y < item.Y+item.Height {
			return index
		}
	}
	return -1
}

func (n *navigationBar) overflowWidth() int {
	if n.widget != nil && n.totalWidth > n.widget.ClientBoundsPixels().Width {
		return n.widget.IntFrom96DPI(26)
	}
	return 0
}

func (n *navigationBar) mouseDown(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton {
		return
	}
	controlWidth := n.overflowWidth()
	if controlWidth > 0 && (x < controlWidth || x >= n.widget.ClientBoundsPixels().Width-controlWidth) {
		step := (n.widget.ClientBoundsPixels().Width - 2*controlWidth) / 2
		if x < controlWidth {
			n.scrollX -= step
		} else {
			n.scrollX += step
		}
		if n.scrollX < 0 {
			n.scrollX = 0
		}
		maxScroll := n.totalWidth - n.widget.ClientBoundsPixels().Width + 2*controlWidth
		if n.scrollX > maxScroll {
			n.scrollX = maxScroll
		}
		n.revealFocus = false
		n.pressed = -1
	} else {
		n.pressed = n.itemAt(x, y)
	}
	if n.widget != nil {
		_ = n.widget.SetFocus()
		_ = n.widget.Invalidate()
	}
}

func (n *navigationBar) mouseMove(x, y int, _ walk.MouseButton) {
	index := n.itemAt(x, y)
	if index == n.hover {
		return
	}
	n.hover = index
	if n.widget != nil {
		_ = n.widget.Invalidate()
	}
}

func (n *navigationBar) mouseUp(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton {
		return
	}
	index := n.itemAt(x, y)
	pressed := n.pressed
	n.pressed = -1
	if index >= 0 && index == pressed {
		n.activate(index)
	} else if n.widget != nil {
		_ = n.widget.Invalidate()
	}
}

func (n *navigationBar) keyDown(key walk.Key) {
	if len(n.labels) == 0 {
		return
	}
	switch key {
	case walk.KeyLeft:
		n.focusIndex = (n.focusIndex - 1 + len(n.labels)) % len(n.labels)
		n.activate(n.focusIndex)
	case walk.KeyRight:
		n.focusIndex = (n.focusIndex + 1) % len(n.labels)
		n.activate(n.focusIndex)
	case walk.KeyHome:
		n.activate(0)
	case walk.KeyEnd:
		n.activate(len(n.labels) - 1)
	case walk.KeyReturn, walk.KeySpace:
		n.activate(n.focusIndex)
	}
}

func (n *navigationBar) paint(canvas *walk.Canvas, _ walk.Rectangle) error {
	if n.widget == nil {
		return nil
	}
	bounds := n.widget.ClientBoundsPixels()
	background, err := walk.NewSolidColorBrush(legacyLight.Surface)
	if err != nil {
		return err
	}
	defer background.Dispose()
	if err := canvas.FillRectanglePixels(background, bounds); err != nil {
		return err
	}

	hoverBrush, err := walk.NewSolidColorBrush(legacyLight.Hover)
	if err != nil {
		return err
	}
	defer hoverBrush.Dispose()
	selectedBrush, err := walk.NewSolidColorBrush(legacyLight.Selected)
	if err != nil {
		return err
	}
	defer selectedBrush.Dispose()
	accentBrush, err := walk.NewSolidColorBrush(legacyLight.Accent)
	if err != nil {
		return err
	}
	defer accentBrush.Dispose()
	separatorBrush, err := walk.NewSolidColorBrush(legacyLight.Separator)
	if err != nil {
		return err
	}
	defer separatorBrush.Dispose()

	font := n.widget.Font()
	activeFont := font
	if bold, err := walk.NewFont(font.Family(), font.PointSize(), walk.FontBold); err == nil {
		activeFont = bold
		defer bold.Dispose()
	}
	padding := n.widget.IntFrom96DPI(12)
	hdc := win.GetDC(n.widget.Handle())
	if hdc == 0 {
		return nil
	}
	defer win.ReleaseDC(n.widget.Handle(), hdc)
	logFont := win.LOGFONT{
		LfHeight:         -win.MulDiv(int32(font.PointSize()), int32(n.widget.DPI()), 72),
		LfWeight:         win.FW_NORMAL,
		LfCharSet:        win.DEFAULT_CHARSET,
		LfOutPrecision:   win.OUT_TT_PRECIS,
		LfClipPrecision:  win.CLIP_DEFAULT_PRECIS,
		LfQuality:        win.CLEARTYPE_QUALITY,
		LfPitchAndFamily: win.VARIABLE_PITCH | win.FF_SWISS,
	}
	copy(logFont.LfFaceName[:], syscall.StringToUTF16(font.Family()))
	regularFont := win.CreateFontIndirect(&logFont)
	if regularFont == 0 {
		return nil
	}
	defer win.DeleteObject(win.HGDIOBJ(regularFont))
	logFont.LfWeight = win.FW_BOLD
	boldFont := win.CreateFontIndirect(&logFont)
	if boldFont != 0 {
		defer win.DeleteObject(win.HGDIOBJ(boldFont))
	}
	widths := make([]int, len(n.labels))
	for index, label := range n.labels {
		utf16, err := syscall.UTF16FromString(label)
		if err != nil {
			return err
		}
		measure := func(hFont win.HFONT) int {
			old := win.SelectObject(hdc, win.HGDIOBJ(hFont))
			defer win.SelectObject(hdc, old)
			var size win.SIZE
			if !win.GetTextExtentPoint32(hdc, &utf16[0], int32(len(utf16)-1), &size) {
				return 0
			}
			return int(size.CX)
		}
		width := measure(regularFont)
		if boldFont != 0 {
			if activeWidth := measure(boldFont); activeWidth > width {
				width = activeWidth
			}
		}
		widths[index] = width + padding*2
	}
	controlWidth := 0
	total := 0
	for _, width := range widths {
		total += width
	}
	if total > bounds.Width {
		controlWidth = n.widget.IntFrom96DPI(26)
	}
	if n.lastWidth != bounds.Width || n.lastDPI != n.widget.DPI() {
		n.revealFocus = true
		n.lastWidth = bounds.Width
		n.lastDPI = n.widget.DPI()
	}
	focusIndex := -1
	if n.revealFocus {
		focusIndex = n.focusIndex
		n.revealFocus = false
	}
	n.items, n.scrollX, n.totalWidth = navigationRects(widths, bounds.Width, n.scrollX, focusIndex, controlWidth)
	for index, label := range n.labels {
		itemBounds := n.items[index]
		itemBounds.Height = bounds.Height
		n.items[index].Height = bounds.Height
		if itemBounds.X < controlWidth {
			itemBounds.Width += itemBounds.X - controlWidth
			itemBounds.X = controlWidth
		}
		if itemBounds.X+itemBounds.Width > bounds.Width-controlWidth {
			itemBounds.Width = bounds.Width - controlWidth - itemBounds.X
		}
		if itemBounds.Width < 0 {
			itemBounds.Width = 0
		}
		if itemBounds.Width == 0 {
			continue
		}
		if index == n.current {
			if err := canvas.FillRectanglePixels(selectedBrush, itemBounds); err != nil {
				return err
			}
		} else if index == n.hover || index == n.pressed {
			if err := canvas.FillRectanglePixels(hoverBrush, itemBounds); err != nil {
				return err
			}
		}
		itemFont := font
		textColor := legacyLight.Text
		if index == n.current {
			itemFont = activeFont
			textColor = legacyLight.Accent
		}
		textBounds := itemBounds
		textBounds.X += 2
		textBounds.Width -= 4
		if err := canvas.DrawTextPixels(label, itemFont, textColor, textBounds, walk.TextCenter|walk.TextVCenter|walk.TextSingleLine|walk.TextEndEllipsis|walk.TextNoPrefix); err != nil {
			return err
		}
		if index == n.current {
			underline := walk.Rectangle{X: itemBounds.X + 7, Y: bounds.Height - 2, Width: itemBounds.Width - 14, Height: 2}
			if underline.Width > 0 {
				if err := canvas.FillRectanglePixels(accentBrush, underline); err != nil {
					return err
				}
			}
		}
		if n.widget.Focused() && index == n.focusIndex {
			pen, err := walk.NewCosmeticPen(walk.PenSolid, legacyLight.Accent)
			if err != nil {
				return err
			}
			err = canvas.DrawRectanglePixels(pen, walk.Rectangle{X: itemBounds.X + 2, Y: 2, Width: itemBounds.Width - 4, Height: itemBounds.Height - 5})
			pen.Dispose()
			if err != nil {
				return err
			}
		}
	}
	if controlWidth > 0 {
		leftArrow := walk.Rectangle{X: 0, Y: 0, Width: controlWidth, Height: bounds.Height - 1}
		rightArrow := walk.Rectangle{X: bounds.Width - controlWidth, Y: 0, Width: controlWidth, Height: bounds.Height - 1}
		if err := canvas.FillRectanglePixels(hoverBrush, leftArrow); err != nil {
			return err
		}
		if err := canvas.FillRectanglePixels(hoverBrush, rightArrow); err != nil {
			return err
		}
		if err := canvas.DrawTextPixels("‹", font, legacyLight.Accent, leftArrow, walk.TextCenter|walk.TextVCenter|walk.TextSingleLine); err != nil {
			return err
		}
		if err := canvas.DrawTextPixels("›", font, legacyLight.Accent, rightArrow, walk.TextCenter|walk.TextVCenter|walk.TextSingleLine); err != nil {
			return err
		}
	}
	return canvas.FillRectanglePixels(separatorBrush, walk.Rectangle{X: 0, Y: bounds.Height - 1, Width: bounds.Width, Height: 1})
}
