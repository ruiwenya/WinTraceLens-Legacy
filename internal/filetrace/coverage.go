package filetrace

import (
	"fmt"
	"github.com/ruiwenya/WinTraceLens/internal/coverage"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"path/filepath"
	"sort"
	"strings"
)

func fileCoverage(snapshot Snapshot, opts Options, limit int) *coverage.Summary {
	c := &coverage.Summary{Status: "Observed", Returned: len(snapshot.Records), Limit: limit, LimitScope: "基础痕迹记录；持久化定向补采独立保留", Sort: "原生传统痕迹优先、按来源公平分配配额；不是完整文件时间线", Roots: append([]string(nil), opts.ModifiedRoots...), Warnings: append([]string(nil), snapshot.CollectionErrors...), Boundary: "仅覆盖请求目录、时间窗和可用取证源；取证源状态不等于文件证据，未命中不能证明文件未存在或未执行。"}
	seen := map[string]bool{}
	evidenceCount := 0
	var times []string
	for _, row := range snapshot.Records {
		if row.Category != "取证源状态" && row.Category != "采集提示" {
			evidenceCount++
		}
		if !seen[row.Source] {
			c.Sources = append(c.Sources, row.Source)
			seen[row.Source] = true
		}
		times = append(times, row.EvidenceTime, row.Modified, row.LastRun)
	}
	sort.Strings(c.Sources)
	if evidenceCount == 0 {
		c.Status = "Insufficient telemetry"
	}
	c.Earliest, c.Latest = coverage.Times(times)
	c.LimitReached = len(snapshot.Records) >= limit
	c.PossiblyTruncated = c.LimitReached
	return c
}

// WithPersistence appends independent targeted checks without consuming the
// ordinary trace quota. It never scans a remote path or executes a sample.
func WithPersistence(snapshot Snapshot, machine host.Snapshot) Snapshot {
	base := make([]Record, 0, len(snapshot.Records)+len(machine.TargetedFiles))
	for _, row := range snapshot.Records {
		if row.Source != "持久化定向补采" {
			base = append(base, row)
		}
	}
	for _, entry := range machine.TargetedFiles {
		t := entry.Target
		base = append(base, Record{Category: "持久化载荷", Source: "持久化定向补采", Name: filepath.Base(t.Path), Path: t.Path,
			Directory: filepath.Dir(t.Path), Extension: filepath.Ext(t.Path), Size: t.Size, Created: t.Created, Modified: t.Modified,
			SHA256: t.SHA256, Signature: t.Signature, SignatureMsg: t.SignatureMsg, Suspicion: "中",
			Reason:  strings.Join(entry.References, "；") + "；目标状态：" + t.FileStatus,
			Details: fmt.Sprintf("父目录状态=%s；ACL=%s；ADS=%s；SHA-256=%s；签名=%s；限制=%s；错误=%s %s", entry.DirectoryStatus, entry.DirectoryACL, strings.Join(entry.Streams, "；"), t.SHA256, t.Signature, strings.Join(entry.Warnings, "；"), t.CheckError, t.HashError)})
	}
	snapshot.Records = base
	snapshot.Coverage = coverage.Clone(snapshot.Coverage)
	if snapshot.Coverage != nil {
		snapshot.Coverage.Returned = len(base)
		if len(machine.TargetedFiles) > 0 {
			snapshot.Coverage.Sources = append(snapshot.Coverage.Sources, "持久化定向补采")
		}
	}
	return snapshot
}
