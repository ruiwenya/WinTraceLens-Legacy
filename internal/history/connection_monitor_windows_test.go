//go:build windows

package history

import (
	"testing"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/process"
)

func TestConnectionMonitorRetainsIntermittentSYN(t *testing.T) {
	monitor := NewConnectionMonitor(time.Second, 100)
	monitor.identities[3996] = process.Identity{Name: "sample.exe", Path: `C:\ProgramData\sample.exe`}
	firstSeen := time.Date(2026, 9, 16, 10, 30, 0, 0, time.Local)
	connection := process.ConnectionInfo{
		PID: 3996, Protocol: "TCP4", Local: "192.168.1.20:51000",
		Remote: "203.0.113.8:445", RemoteIP: "203.0.113.8", RemotePort: 445,
		RemoteKind: "公网/外部", State: "SYN-SENT",
	}

	monitor.observe([]process.ConnectionInfo{connection}, firstSeen, nil)
	monitor.observe(nil, firstSeen.Add(time.Second), nil)
	connection.State = "ESTABLISHED"
	monitor.observe([]process.ConnectionInfo{connection}, firstSeen.Add(2*time.Second), nil)

	snapshot := monitor.Snapshot()
	if len(snapshot.Items) != 1 {
		t.Fatalf("expected one retained connection, got %d", len(snapshot.Items))
	}
	item := snapshot.Items[0]
	if item.Occurrences != 2 || item.Samples != 2 || !item.CurrentlyActive {
		t.Fatalf("unexpected counters: occurrences=%d samples=%d active=%v", item.Occurrences, item.Samples, item.CurrentlyActive)
	}
	if item.FirstSeen != "2026-09-16 10:30:00" || item.LastSeen != "2026-09-16 10:30:02" {
		t.Fatalf("unexpected observation window: %s - %s", item.FirstSeen, item.LastSeen)
	}
	if item.Process != "sample.exe" || item.Path == "" || item.State != "ESTABLISHED" {
		t.Fatalf("unexpected retained metadata: %#v", item)
	}
}

func TestConnectionMonitorIgnoresListeners(t *testing.T) {
	monitor := NewConnectionMonitor(time.Second, 100)
	monitor.observe([]process.ConnectionInfo{{
		PID: 4, Protocol: "TCP4", Local: "0.0.0.0:445",
		Remote: "0.0.0.0", RemoteIP: "0.0.0.0", State: "LISTEN",
	}}, time.Now(), nil)
	if count := len(monitor.Snapshot().Items); count != 0 {
		t.Fatalf("expected listener to be ignored, got %d items", count)
	}
}
