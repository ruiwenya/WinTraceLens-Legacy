package history

import (
	"github.com/ruiwenya/WinTraceLens/internal/coverage"
	"sort"
	"strings"
)

func historyCoverage(snapshot Snapshot, limit int) *coverage.Summary {
	c := &coverage.Summary{Status: "Insufficient telemetry", Returned: len(snapshot.Records), Limit: limit, LimitScope: "每来源", Sort: "按来源分别保留；DNS 缓存没有可靠时间和进程归属", Warnings: append([]string(nil), snapshot.CollectionErrors...), Boundary: "关键网络审计源未返回可用历史记录，不能排除历史外联。DNS 缓存、当前连接及本次采样不能恢复未记录的通信。"}
	counts := map[string]int{}
	var times []string
	for _, row := range snapshot.Records {
		counts[row.Source]++
		lower := strings.ToLower(row.Source)
		if row.Time != "" && (strings.Contains(lower, "sysmon") || strings.Contains(lower, "wfp") || strings.Contains(lower, "防火墙") || strings.Contains(lower, "dns client")) {
			c.Status = "Observed"
			times = append(times, row.Time)
		}
	}
	for source, count := range counts {
		c.Sources = append(c.Sources, source)
		if count >= limit {
			c.LimitReached, c.PossiblyTruncated = true, true
		}
	}
	sort.Strings(c.Sources)
	if c.Status == "Observed" {
		c.Boundary = "已观察到部分历史日志，仍受日志启用状态、权限、时间窗和配额限制；未命中不能证明没有历史外联。"
	}
	c.Earliest, c.Latest = coverage.Times(times)
	return c
}
