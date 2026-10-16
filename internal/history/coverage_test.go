package history

import "testing"

func TestDNSAndCurrentSnapshotsCannotProveHistory(t *testing.T) {
	base := Snapshot{Records: []Record{{Source: "DNS 缓存", Query: "example.test"}, {Source: "netstat 快照", Time: "2026-10-14 12:00:00"}}}
	if got := historyCoverage(base, 500); got.Status != "Insufficient telemetry" || got.Earliest != "" {
		t.Fatalf("snapshot treated as history: %+v", got)
	}
	base.Records = append(base.Records, Record{Source: "安全日志 WFP", Time: "2026-10-14 11:00:00", EventID: "5156"})
	if got := historyCoverage(base, 1); got.Status != "Observed" || !got.LimitReached {
		t.Fatalf("historical coverage missing: %+v", got)
	}
}
