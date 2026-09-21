//go:build windows

package main

import (
	"strings"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
)

type legacyPalette struct {
	Surface           walk.Color
	Chrome            walk.Color
	TitleBar          walk.Color
	Text              walk.Color
	MutedText         walk.Color
	Border            walk.Color
	Separator         walk.Color
	Alternate         walk.Color
	Hover             walk.Color
	Selected          walk.Color
	Accent            walk.Color
	SummaryBackground walk.Color
	SummaryText       walk.Color
	WarningText       walk.Color
	WarningBackground walk.Color
	DangerText        walk.Color
	DangerBackground  walk.Color
	SuccessText       walk.Color
}

var legacyLight = legacyPalette{
	Surface:           walk.RGB(255, 255, 255),
	Chrome:            walk.RGB(244, 245, 247),
	TitleBar:          walk.RGB(247, 248, 250),
	Text:              walk.RGB(37, 42, 50),
	MutedText:         walk.RGB(96, 105, 118),
	Border:            walk.RGB(215, 220, 227),
	Separator:         walk.RGB(236, 239, 243),
	Alternate:         walk.RGB(250, 251, 252),
	Hover:             walk.RGB(240, 243, 248),
	Selected:          walk.RGB(232, 240, 253),
	Accent:            walk.RGB(36, 93, 209),
	SummaryBackground: walk.RGB(240, 245, 253),
	SummaryText:       walk.RGB(36, 78, 145),
	WarningText:       walk.RGB(144, 84, 9),
	WarningBackground: walk.RGB(255, 243, 222),
	DangerText:        walk.RGB(156, 42, 42),
	DangerBackground:  walk.RGB(255, 235, 235),
	SuccessText:       walk.RGB(34, 114, 73),
}

func legacyBrush(color walk.Color) declarative.SolidColorBrush {
	return declarative.SolidColorBrush{Color: color}
}

func legacyFont(pointSize int, bold bool) declarative.Font {
	return declarative.Font{Family: "Microsoft YaHei UI", PointSize: pointSize, Bold: bold}
}

func styleLegacyTableCell(model *tableModel, columns []tableColumn, style *walk.CellStyle) {
	row := style.Row()
	col := style.Col()
	if model == nil || row < 0 || row >= len(model.rows) || col < 0 || col >= len(columns) || col >= len(model.rows[row]) {
		return
	}
	title := strings.TrimSpace(columns[col].Title)
	value := strings.TrimSpace(model.rows[row][col])
	lower := strings.ToLower(value)
	if row%2 == 1 {
		style.BackgroundColor = legacyLight.Alternate
	}

	if strings.Contains(title, "路径") || strings.Contains(title, "位置") || title == "命令" || title == "命令行" {
		style.TextColor = legacyLight.MutedText
	}

	switch {
	case title == "风险" || title == "级别":
		styleRiskValue(style, value)
	case title == "可疑" && (value == "是" || value == "高" || value == "中"):
		style.TextColor = legacyLight.WarningText
		style.BackgroundColor = legacyLight.WarningBackground
	case strings.Contains(title, "签名"):
		switch {
		case strings.Contains(lower, "无签名") || strings.Contains(lower, "未签名") || strings.Contains(lower, "异常") || strings.Contains(lower, "失败") || strings.Contains(lower, "invalid"):
			style.TextColor = legacyLight.WarningText
		case strings.Contains(lower, "已签名") || strings.Contains(lower, "有效") || strings.Contains(lower, "系统文件") || strings.Contains(lower, "valid"):
			style.TextColor = legacyLight.SuccessText
		}
	case strings.Contains(title, "错误") && value != "":
		style.TextColor = legacyLight.DangerText
		style.BackgroundColor = legacyLight.DangerBackground
	case title == "状态" || title == "运行状态" || title == "动作":
		if strings.Contains(value, "成功") || strings.Contains(value, "运行") || strings.Contains(value, "允许") || strings.Contains(value, "启用") {
			style.TextColor = legacyLight.SuccessText
		} else if strings.Contains(value, "失败") || strings.Contains(value, "拒绝") || strings.Contains(value, "阻止") {
			style.TextColor = legacyLight.DangerText
		}
	}
}

func styleRiskValue(style *walk.CellStyle, value string) {
	switch {
	case strings.Contains(value, "高") || strings.EqualFold(value, "critical"):
		style.TextColor = legacyLight.DangerText
		style.BackgroundColor = legacyLight.DangerBackground
	case strings.Contains(value, "中") || strings.Contains(value, "注意") || strings.Contains(value, "需核查"):
		style.TextColor = legacyLight.WarningText
		style.BackgroundColor = legacyLight.WarningBackground
	case strings.Contains(value, "低"):
		style.TextColor = legacyLight.MutedText
	}
}

func (a *legacyApp) applyTableVisuals() {
	for _, table := range []*walk.TableView{
		a.processView, a.moduleView, a.connView, a.hostView,
		a.findingView, a.memoryView, a.driverView, a.eventView,
		a.historyConnectionView, a.historyDNSView, a.historyLiveView,
		a.historyMonitorView, a.historyAllView,
		a.fileTraceView, a.registryView,
	} {
		if table == nil {
			continue
		}
		table.SetGridlines(false)
		table.SetAlternatingRowBG(true)
	}
}
