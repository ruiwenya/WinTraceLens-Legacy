//go:build windows

package main

import (
	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

type navigationBar struct {
	widget     *walk.CustomWidget
	labels     []string
	current    int
	focusIndex int
	hover      int
	pressed    int
	onActivate func(int)
}

func newNavigationBar(labels []string, onActivate func(int)) *navigationBar {
	return &navigationBar{
		labels:     append([]string(nil), labels...),
		current:    0,
		focusIndex: 0,
		hover:      -1,
		pressed:    -1,
		onActivate: onActivate,
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
	if n.widget != nil {
		_ = n.widget.Invalidate()
	}
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
	bounds := n.widget.ClientBoundsPixels()
	if x < 0 || y < 0 || x >= bounds.Width || y >= bounds.Height {
		return -1
	}
	index := x * len(n.labels) / bounds.Width
	if index >= len(n.labels) {
		index = len(n.labels) - 1
	}
	return index
}

func (n *navigationBar) mouseDown(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton {
		return
	}
	n.pressed = n.itemAt(x, y)
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
	activeFont, fontErr := walk.NewFont("Microsoft YaHei UI", 9, walk.FontBold)
	if fontErr != nil {
		activeFont = font
	}
	for index, label := range n.labels {
		left := index * bounds.Width / len(n.labels)
		right := (index + 1) * bounds.Width / len(n.labels)
		itemBounds := walk.Rectangle{X: left, Y: 0, Width: right - left, Height: bounds.Height}
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
		textBounds.X += 4
		textBounds.Width -= 8
		if err := canvas.DrawTextPixels(label, itemFont, textColor, textBounds, walk.TextCenter|walk.TextVCenter|walk.TextSingleLine|walk.TextEndEllipsis|walk.TextNoPrefix); err != nil {
			return err
		}
		if index == n.current {
			underline := walk.Rectangle{X: left + 8, Y: bounds.Height - 3, Width: right - left - 16, Height: 3}
			if underline.Width > 0 {
				if err := canvas.FillRectanglePixels(accentBrush, underline); err != nil {
					return err
				}
			}
		}
	}
	return canvas.FillRectanglePixels(separatorBrush, walk.Rectangle{X: 0, Y: bounds.Height - 1, Width: bounds.Width, Height: 1})
}
