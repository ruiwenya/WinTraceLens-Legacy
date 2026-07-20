//go:build !windows

package driveranalysis

import "errors"

func Collect(opts Options) (Snapshot, error) {
	return Snapshot{}, errors.New("driver analysis is only supported on Windows")
}
