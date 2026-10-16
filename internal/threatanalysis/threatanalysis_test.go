package threatanalysis

import (
	"github.com/ruiwenya/WinTraceLens/internal/commandchain"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"strings"
	"testing"
)

func TestMissingPersistencePayloadNotMaskedBySystemLauncher(t *testing.T) {
	path := `C:\CustomRoot\missing.bin`
	chain := &commandchain.Chain{Launcher: commandchain.Target{Kind: "file", Path: `C:\Windows\System32\cmd.exe`, MD5: "launcher-md5", Signature: "系统文件"}, Payloads: []commandchain.Target{{Kind: "file", Path: path, FileStatus: "文件不存在"}}}
	snapshot := host.Snapshot{Services: []host.ServiceInfo{{Name: "fixture", State: "Stopped", Path: chain.Launcher.Path, MD5: "launcher-md5", Signature: "系统文件", ExecutionChain: chain, RiskLevel: "高", RiskScore: 9, RiskReasons: []string{"异步启动的后续目标文件缺失"}}}}
	rows := standalonePersistence(snapshot, map[string]struct{}{})
	if len(rows) != 1 || rows[0].Level != "高" || rows[0].Path != path || rows[0].MD5 != "" || rows[0].Signature == "系统文件" {
		t.Fatalf("payload risk hidden: %+v", rows)
	}
	if !strings.Contains(strings.Join(buildPersistenceIndex(snapshot)[normalizePath(path)], "；"), "后续目标") {
		t.Fatal("payload missing from process correlation index")
	}
}
