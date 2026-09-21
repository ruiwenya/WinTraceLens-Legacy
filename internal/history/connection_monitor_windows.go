//go:build windows

package history

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/process"
)

const (
	DefaultConnectionMonitorInterval = time.Second
	DefaultConnectionMonitorCapacity = 5000
)

type ObservedConnection struct {
	PID             uint32
	Process         string
	Path            string
	Protocol        string
	Local           string
	Remote          string
	RemoteIP        string
	RemotePort      uint16
	RemoteKind      string
	State           string
	FirstSeen       string
	LastSeen        string
	Occurrences     uint64
	Samples         uint64
	CurrentlyActive bool

	firstSeenTime time.Time
	lastSeenTime  time.Time
}

type ConnectionMonitorSnapshot struct {
	Items       []ObservedConnection
	StartedAt   string
	GeneratedAt string
	LastError   string
	Interval    time.Duration
	Capacity    int
}

type ConnectionMonitor struct {
	mu         sync.Mutex
	startOnce  sync.Once
	stopOnce   sync.Once
	interval   time.Duration
	capacity   int
	stop       chan struct{}
	done       chan struct{}
	started    chan struct{}
	startedAt  time.Time
	lastError  string
	items      map[string]*ObservedConnection
	active     map[string]struct{}
	identities map[uint32]process.Identity
}

func NewConnectionMonitor(interval time.Duration, capacity int) *ConnectionMonitor {
	if interval <= 0 {
		interval = DefaultConnectionMonitorInterval
	}
	if capacity <= 0 {
		capacity = DefaultConnectionMonitorCapacity
	}
	return &ConnectionMonitor{
		interval:   interval,
		capacity:   capacity,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		started:    make(chan struct{}),
		items:      make(map[string]*ObservedConnection),
		active:     make(map[string]struct{}),
		identities: make(map[uint32]process.Identity),
	}
}

func (m *ConnectionMonitor) Start() {
	m.startOnce.Do(func() {
		m.mu.Lock()
		m.startedAt = time.Now()
		m.mu.Unlock()
		close(m.started)
		go m.loop()
	})
}

func (m *ConnectionMonitor) Stop() {
	m.stopOnce.Do(func() { close(m.stop) })
	select {
	case <-m.started:
		select {
		case <-m.done:
		case <-time.After(2 * time.Second):
		}
	default:
	}
}

func (m *ConnectionMonitor) Snapshot() ConnectionMonitorSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]ObservedConnection, 0, len(m.items))
	for _, source := range m.items {
		item := *source
		item.FirstSeen = formatMonitorTime(item.firstSeenTime)
		item.LastSeen = formatMonitorTime(item.lastSeenTime)
		item.firstSeenTime = time.Time{}
		item.lastSeenTime = time.Time{}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen == items[j].LastSeen {
			return items[i].Remote < items[j].Remote
		}
		return items[i].LastSeen > items[j].LastSeen
	})
	return ConnectionMonitorSnapshot{
		Items:       items,
		StartedAt:   formatMonitorTime(m.startedAt),
		GeneratedAt: formatMonitorTime(time.Now()),
		LastError:   m.lastError,
		Interval:    m.interval,
		Capacity:    m.capacity,
	}
}

func (m *ConnectionMonitor) loop() {
	defer close(m.done)
	m.collectOnce()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.collectOnce()
		case <-m.stop:
			return
		}
	}
}

func (m *ConnectionMonitor) collectOnce() {
	connections, err := process.CollectConnections()
	if err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return
	}

	unknown := make([]uint32, 0)
	seenPID := make(map[uint32]struct{})
	m.mu.Lock()
	for _, item := range connections {
		if !monitorableConnection(item) {
			continue
		}
		if _, ok := m.identities[item.PID]; ok {
			continue
		}
		if _, ok := seenPID[item.PID]; ok {
			continue
		}
		seenPID[item.PID] = struct{}{}
		unknown = append(unknown, item.PID)
	}
	m.mu.Unlock()

	var identityErr error
	if len(unknown) > 0 {
		identities, err := process.ResolveIdentities(unknown)
		identityErr = err
		if err == nil {
			m.mu.Lock()
			for pid, identity := range identities {
				m.identities[pid] = identity
			}
			m.mu.Unlock()
		}
	}
	m.observe(connections, time.Now(), identityErr)
}

func (m *ConnectionMonitor) observe(connections []process.ConnectionInfo, observedAt time.Time, collectionErr error) {
	current := make(map[string]struct{}, len(connections))
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, item := range connections {
		if !monitorableConnection(item) {
			continue
		}
		key := monitoredConnectionKey(item)
		current[key] = struct{}{}
		identity := m.identities[item.PID]
		record, exists := m.items[key]
		if !exists {
			record = &ObservedConnection{
				PID:           item.PID,
				Process:       identity.Name,
				Path:          identity.Path,
				Protocol:      item.Protocol,
				Local:         item.Local,
				Remote:        item.Remote,
				RemoteIP:      item.RemoteIP,
				RemotePort:    item.RemotePort,
				RemoteKind:    item.RemoteKind,
				State:         item.State,
				Occurrences:   1,
				firstSeenTime: observedAt,
			}
			m.items[key] = record
		} else if _, wasActive := m.active[key]; !wasActive {
			record.Occurrences++
		}
		if record.Process == "" {
			record.Process = identity.Name
		}
		if record.Path == "" {
			record.Path = identity.Path
		}
		record.RemoteKind = firstMonitorValue(item.RemoteKind, record.RemoteKind)
		record.State = item.State
		record.lastSeenTime = observedAt
		record.Samples++
		record.CurrentlyActive = true
	}
	for key := range m.active {
		if _, ok := current[key]; ok {
			continue
		}
		if record := m.items[key]; record != nil {
			record.CurrentlyActive = false
		}
	}
	m.active = current
	if collectionErr != nil {
		m.lastError = "进程信息补充失败: " + collectionErr.Error()
	} else {
		m.lastError = ""
	}
	m.pruneLocked()
}

func (m *ConnectionMonitor) pruneLocked() {
	if len(m.items) <= m.capacity {
		return
	}
	type candidate struct {
		key    string
		active bool
		seen   time.Time
	}
	candidates := make([]candidate, 0, len(m.items))
	for key, item := range m.items {
		candidates = append(candidates, candidate{key: key, active: item.CurrentlyActive, seen: item.lastSeenTime})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].active != candidates[j].active {
			return !candidates[i].active
		}
		return candidates[i].seen.Before(candidates[j].seen)
	})
	for len(m.items) > m.capacity {
		item := candidates[0]
		candidates = candidates[1:]
		delete(m.items, item.key)
		delete(m.active, item.key)
	}
}

func monitorableConnection(item process.ConnectionInfo) bool {
	ip := strings.TrimSpace(item.RemoteIP)
	return item.RemotePort != 0 && ip != "" && ip != "0.0.0.0" && ip != "::" && ip != "*"
}

func monitoredConnectionKey(item process.ConnectionInfo) string {
	return fmt.Sprintf("%d|%s|%s|%s", item.PID, strings.ToUpper(item.Protocol), item.Local, item.Remote)
}

func formatMonitorTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format("2006-01-02 15:04:05")
}

func firstMonitorValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
