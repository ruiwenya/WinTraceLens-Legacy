// Package coverage describes what a collection can and cannot establish.
package coverage

import (
	"fmt"
	"sort"
	"strings"
)

type Summary struct {
	Status            string   `json:"status"`
	Returned          int      `json:"returned"`
	Limit             int      `json:"limit"`
	LimitScope        string   `json:"limitScope"`
	LimitReached      bool     `json:"limitReached"`
	PossiblyTruncated bool     `json:"possiblyTruncated"`
	Sort              string   `json:"sort"`
	Earliest          string   `json:"earliest,omitempty"`
	Latest            string   `json:"latest,omitempty"`
	Roots             []string `json:"roots,omitempty"`
	Sources           []string `json:"sources,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
	Boundary          string   `json:"boundary"`
}

func Times(values []string) (string, string) {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	if len(filtered) == 0 {
		return "", ""
	}
	sort.Strings(filtered)
	return filtered[0], filtered[len(filtered)-1]
}

func Clone(value *Summary) *Summary {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Roots = append([]string(nil), value.Roots...)
	copy.Sources = append([]string(nil), value.Sources...)
	copy.Warnings = append([]string(nil), value.Warnings...)
	return &copy
}

func Describe(value *Summary) string {
	if value == nil {
		return "尚未采集覆盖信息。"
	}
	status := "已返回部分可观察证据"
	if value.Status == "Insufficient telemetry" {
		status = "数据源不足"
	}
	lines := []string{status, fmt.Sprintf("返回 %d 条；上限 %d（%s）", value.Returned, value.Limit, value.LimitScope), "排序 / 保留方式：" + value.Sort}
	if value.LimitReached || value.PossiblyTruncated {
		lines = append(lines, "已达到配额或可能截断；未命中不能视为没有该项行为。")
	}
	if value.Earliest != "" {
		lines = append(lines, "已返回记录时间范围："+value.Earliest+" 至 "+value.Latest)
	}
	if len(value.Roots) > 0 {
		lines = append(lines, "请求扫描目录："+strings.Join(value.Roots, "；"))
	}
	lines = append(lines, "已返回来源："+strings.Join(value.Sources, "；"), value.Boundary)
	lines = append(lines, value.Warnings...)
	return strings.Join(lines, "\r\n")
}
