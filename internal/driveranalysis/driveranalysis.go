package driveranalysis

type Options struct {
	HashLimitBytes int64
	MaxRecords     int
	MaxEvents      int
}

type Snapshot struct {
	Items            []Item        `json:"items"`
	Checks           []SourceCheck `json:"checks"`
	CollectionErrors []string      `json:"collectionErrors"`
	GeneratedAt      string        `json:"generatedAt"`
	SourceSummary    string        `json:"sourceSummary"`
	SourceCounts     SourceCounts  `json:"sourceCounts"`
}

type SourceCounts struct {
	KernelModules   int `json:"kernelModules"`
	RegistryDrivers int `json:"registryDrivers"`
	DiskDrivers     int `json:"diskDrivers"`
	LoadEvents      int `json:"loadEvents"`
}

type SourceCheck struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Count  int    `json:"count"`
	Detail string `json:"detail"`
}

type Item struct {
	Level        string `json:"level"`
	Score        int    `json:"score"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Signature    string `json:"signature"`
	SignatureMsg string `json:"signatureMsg"`
	MD5          string `json:"md5"`
	HashError    string `json:"hashError"`
	BaseAddress  string `json:"baseAddress"`
	SizeKB       uint32 `json:"sizeKb"`
	Path         string `json:"path"`
	ServiceName  string `json:"serviceName"`
	ServiceStart string `json:"serviceStart"`
	ServiceType  string `json:"serviceType"`
	ServiceImage string `json:"serviceImage"`
	RegistryPath string `json:"registryPath"`
	EventMatches string `json:"eventMatches"`
	DiskPath     string `json:"diskPath"`
	SourceDiff   string `json:"sourceDiff"`
	Reason       string `json:"reason"`
	Evidence     string `json:"evidence"`
}
