//go:build windows

package main

import (
	"testing"

	"github.com/lxn/walk"
)

func TestNavigationRectsAndHitMapping(t *testing.T) {
	widths := []int{90, 100, 80}
	items, scroll, total := navigationRects(widths, 400, 0, 0, 0)
	if scroll != 0 || total != 270 {
		t.Fatalf("unexpected scroll=%d total=%d", scroll, total)
	}
	for i := range items {
		items[i].Height = 35
		center := items[i].X + items[i].Width/2
		for _, x := range []int{items[i].X, center, items[i].X + items[i].Width - 1} {
			if hit := navigationItemAt(items, x, 17, walk.Rectangle{Width: 400, Height: 35}, 0); hit != i {
				t.Fatalf("x=%d hit item %d, want %d", x, hit, i)
			}
		}
		if i > 0 && items[i-1].X+items[i-1].Width != items[i].X {
			t.Fatalf("item %d has a gap or overlap", i)
		}
	}
	if hit := navigationItemAt(items, 270, 17, walk.Rectangle{Width: 400, Height: 35}, 0); hit != -1 {
		t.Fatalf("empty nav area hit item %d", hit)
	}
}

func TestNavigationOverflowKeepsFocusVisible(t *testing.T) {
	widths := []int{90, 100, 80, 110}
	items, scroll, total := navigationRects(widths, 220, 0, 3, 26)
	if total != 380 || scroll != 212 {
		t.Fatalf("unexpected total=%d scroll=%d", total, scroll)
	}
	if items[3].X < 26 || items[3].X+items[3].Width > 220-26 {
		t.Fatalf("focused item not visible: %+v", items[3])
	}
	for i := range items {
		items[i].Height = 35
	}
	if hit := navigationItemAt(items, 194, 17, walk.Rectangle{Width: 220, Height: 35}, 26); hit != -1 {
		t.Fatalf("overflow arrow hit item %d", hit)
	}
	_, preserved, _ := navigationRects(widths, 220, 80, -1, 26)
	if preserved != 80 {
		t.Fatalf("manual overflow scroll was lost: %d", preserved)
	}
	_, clamped, _ := navigationRects(widths, 220, 999, -1, 26)
	if clamped != 212 {
		t.Fatalf("overflow scroll not clamped: %d", clamped)
	}
}
