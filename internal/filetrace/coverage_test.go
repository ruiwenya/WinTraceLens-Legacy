package filetrace

import (
	"github.com/ruiwenya/WinTraceLens/internal/commandchain"
	"github.com/ruiwenya/WinTraceLens/internal/host"
	"testing"
)

func TestTargetedTracesIndependentAndIdempotent(t *testing.T) {
	base := Snapshot{Records: []Record{{Source: "Prefetch", Name: "fixture"}}}
	base.Coverage = fileCoverage(base, Options{ModifiedRoots: []string{`C:\CustomRoot`}}, 1)
	machine := host.Snapshot{TargetedFiles: []host.TargetedFile{{Target: commandchain.Target{Path: `C:\CustomRoot\fixture.bin`, Kind: "file", FileStatus: "文件不存在"}, References: []string{"服务：fixture"}}}}
	result := WithPersistence(WithPersistence(base, machine), machine)
	if len(result.Records) != 2 || len(base.Records) != 1 || result.Coverage.Returned != 2 || base.Coverage.Returned != 1 || !result.Coverage.LimitReached {
		t.Fatalf("quota/idempotence lost: %+v", result)
	}
	if result.Records[1].SHA256 != "" {
		t.Fatal("missing target borrowed a hash")
	}
}

func TestOnlySourceStatusIsNotFileEvidence(t *testing.T) {
	value := fileCoverage(Snapshot{Records: []Record{{Category: "取证源状态", Source: "Prefetch"}}}, Options{}, 500)
	if value.Status != "Insufficient telemetry" {
		t.Fatal("unavailable sources counted as observed evidence")
	}
}
