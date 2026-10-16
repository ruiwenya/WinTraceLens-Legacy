package securitylog

import (
	"github.com/ruiwenya/WinTraceLens/internal/coverage"
	"sort"
)

func eventCoverage(snapshot Snapshot, limit int) *coverage.Summary {
	c := &coverage.Summary{Status: "Observed", Returned: len(snapshot.Events), Limit: limit, LimitScope: "每来源查询；服务定向事件独立保全", Sort: "各事件源按时间降序查询后合并，不代表完整日志", Warnings: append([]string(nil), snapshot.CollectionErrors...), Boundary: "仅覆盖所选时间、权限允许且存在的日志与事件类型。无记录不能证明相关操作从未发生。"}
	seen := map[string]bool{}
	counts := map[string]int{}
	var times []string
	for _, row := range snapshot.Events {
		if !seen[row.Source] {
			c.Sources = append(c.Sources, row.Source)
			seen[row.Source] = true
		}
		counts[row.Source]++
		times = append(times, row.Time)
	}
	sort.Strings(c.Sources)
	c.Earliest, c.Latest = coverage.Times(times)
	for _, count := range counts {
		if count >= limit {
			c.LimitReached = true
		}
	}
	c.PossiblyTruncated = c.LimitReached || len(snapshot.CollectionErrors) > 0
	if len(snapshot.Events) == 0 {
		c.Status = "Insufficient telemetry"
	}
	return c
}
