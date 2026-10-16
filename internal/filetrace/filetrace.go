package filetrace

import "github.com/ruiwenya/WinTraceLens/internal/coverage"

type Options struct {
	MaxRecords    int
	Hours         int
	ModifiedRoots []string
}

type Snapshot struct {
	Coverage         *coverage.Summary `json:"coverage,omitempty"`
	Records          []Record          `json:"records"`
	CollectionErrors []string          `json:"collectionErrors"`
	GeneratedAt      string            `json:"generatedAt"`
}

type Record struct {
	Category     string `json:"category"`
	Source       string `json:"source"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	Directory    string `json:"directory"`
	Extension    string `json:"extension"`
	Size         int64  `json:"size"`
	Created      string `json:"created"`
	Modified     string `json:"modified"`
	Accessed     string `json:"accessed"`
	LastRun      string `json:"lastRun"`
	RunCount     string `json:"runCount"`
	Suspicion    string `json:"suspicion"`
	Reason       string `json:"reason"`
	Details      string `json:"details"`
	EvidenceTime string `json:"evidenceTime,omitempty"`
	TimeMeaning  string `json:"timeMeaning,omitempty"`
	SHA1         string `json:"sha1,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Signature    string `json:"signature,omitempty"`
	SignatureMsg string `json:"signatureMsg,omitempty"`
	Schema       string `json:"schema,omitempty"`
	Association  string `json:"association,omitempty"`
}
