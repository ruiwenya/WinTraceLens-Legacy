//go:build windows

package process

import (
	"os"
	"testing"
)

func TestResolveIdentitiesCurrentProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	identities, err := ResolveIdentities([]uint32{pid})
	if err != nil {
		t.Fatalf("ResolveIdentities failed: %v", err)
	}
	identity, ok := identities[pid]
	if !ok {
		t.Fatalf("current PID %d was not resolved", pid)
	}
	if identity.Name == "" {
		t.Fatal("current process name is empty")
	}
	if identity.Path == "" {
		t.Fatal("current process path is empty")
	}
}
