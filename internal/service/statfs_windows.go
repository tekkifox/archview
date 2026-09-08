//go:build windows

package service

import "fmt"

type fsStat struct {
	total       uint64
	free        uint64
	used        uint64
	usedPercent float64
}

func statFS(path string) (fsStat, error) {
	return fsStat{}, fmt.Errorf("disk stats unavailable on windows for %s", path)
}