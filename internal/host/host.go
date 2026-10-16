package host

import (
	"github.com/ruiwenya/WinTraceLens/internal/commandchain"
	"github.com/ruiwenya/WinTraceLens/internal/securitylog"
)

type Options struct {
	HashLimitBytes int64
}

type Snapshot struct {
	Services         []ServiceInfo                `json:"services"`
	ScheduledTasks   []ScheduledTaskInfo          `json:"scheduledTasks"`
	StartupItems     []StartupItem                `json:"startupItems"`
	Users            []UserInfo                   `json:"users"`
	ImageHijacks     []ImageHijackInfo            `json:"imageHijacks"`
	PersistenceItems []PersistenceInfo            `json:"persistenceItems"`
	CollectionErrors []string                     `json:"collectionErrors"`
	TargetedFiles    []TargetedFile               `json:"targetedFiles,omitempty"`
	MatchedEvents    []securitylog.PreservedEvent `json:"matchedEvents,omitempty"`
}

type ServiceInfo struct {
	ExecutionChain *commandchain.Chain `json:"executionChain,omitempty"`
	StateNotice    string              `json:"stateNotice,omitempty"`
	FileStatus     string              `json:"fileStatus,omitempty"`
	RiskLevel      string              `json:"riskLevel,omitempty"`
	RiskScore      int                 `json:"riskScore"`
	RiskReasons    []string            `json:"riskReasons,omitempty"`
	Name           string              `json:"name"`
	DisplayName    string              `json:"displayName"`
	State          string              `json:"state"`
	StartMode      string              `json:"startMode"`
	Account        string              `json:"account"`
	Command        string              `json:"command"`
	Path           string              `json:"path"`
	MD5            string              `json:"md5"`
	Signature      string              `json:"signature"`
	SignatureMsg   string              `json:"signatureMsg"`
	HashError      string              `json:"hashError"`
}

type ScheduledTaskInfo struct {
	WorkingDirectory string              `json:"workingDirectory,omitempty"`
	ExecutionChain   *commandchain.Chain `json:"executionChain,omitempty"`
	RiskLevel        string              `json:"riskLevel,omitempty"`
	RiskScore        int                 `json:"riskScore"`
	RiskReasons      []string            `json:"riskReasons,omitempty"`
	Name             string              `json:"name"`
	Path             string              `json:"path"`
	State            string              `json:"state"`
	Status           string              `json:"status"`
	Author           string              `json:"author"`
	Command          string              `json:"command"`
	Arguments        string              `json:"arguments"`
	Executable       string              `json:"executable"`
	MD5              string              `json:"md5"`
	Signature        string              `json:"signature"`
	SignatureMsg     string              `json:"signatureMsg"`
	HashError        string              `json:"hashError"`
}

type StartupItem struct {
	ExecutionChain *commandchain.Chain `json:"executionChain,omitempty"`
	RiskLevel      string              `json:"riskLevel,omitempty"`
	RiskScore      int                 `json:"riskScore"`
	RiskReasons    []string            `json:"riskReasons,omitempty"`
	Source         string              `json:"source"`
	Name           string              `json:"name"`
	Command        string              `json:"command"`
	Location       string              `json:"location"`
	Path           string              `json:"path"`
	MD5            string              `json:"md5"`
	Signature      string              `json:"signature"`
	SignatureMsg   string              `json:"signatureMsg"`
	HashError      string              `json:"hashError"`
}

type UserInfo struct {
	Name             string `json:"name"`
	SID              string `json:"sid"`
	Disabled         bool   `json:"disabled"`
	Lockout          bool   `json:"lockout"`
	PasswordRequired bool   `json:"passwordRequired"`
	LocalAccount     bool   `json:"localAccount"`
}

type ImageHijackInfo struct {
	Image        string `json:"image"`
	Debugger     string `json:"debugger"`
	RegistryPath string `json:"registryPath"`
	Path         string `json:"path"`
	MD5          string `json:"md5"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	HashError    string `json:"hashError"`
}

type PersistenceInfo struct {
	ExecutionChain *commandchain.Chain `json:"executionChain,omitempty"`
	RiskLevel      string              `json:"riskLevel,omitempty"`
	RiskScore      int                 `json:"riskScore"`
	RiskReasons    []string            `json:"riskReasons,omitempty"`
	Category       string              `json:"category"`
	Name           string              `json:"name"`
	Value          string              `json:"value"`
	Location       string              `json:"location"`
	Path           string              `json:"path"`
	MD5            string              `json:"md5"`
	Signature      string              `json:"signature"`
	SignatureMsg   string              `json:"signatureMsg"`
	HashError      string              `json:"hashError"`
}

type TargetedFile struct {
	Target          commandchain.Target   `json:"target"`
	References      []string              `json:"references"`
	DirectoryStatus string                `json:"directoryStatus"`
	DirectoryACL    string                `json:"directoryAcl,omitempty"`
	Streams         []string              `json:"streams,omitempty"`
	NearbyFiles     []commandchain.Target `json:"nearbyFiles,omitempty"`
	Warnings        []string              `json:"warnings,omitempty"`
}

// Never borrow the interpreter's identity for a missing/unresolved child.
func PersistenceTarget(chain *commandchain.Chain, fallback commandchain.Target) commandchain.Target {
	if chain == nil {
		return fallback
	}
	for _, target := range chain.Payloads {
		if !commandchain.IsInterpreter(target.Path) {
			if target.Path == "" {
				target.Path = target.Raw
			}
			return target
		}
	}
	return chain.Launcher
}
