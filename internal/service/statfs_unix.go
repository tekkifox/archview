//go:build !windows

package service

import "syscall"

type fsStat struct {
	total       uint64
	free        uint64
	used        uint64
	usedPercent float64
}

func statFS(path string) (fsStat, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fsStat{}, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free
	usedPercent := 0.0
	if total > 0 {
		usedPercent = float64(used) / float64(total) * 100
	}
	return fsStat{total: total, free: free, used: used, usedPercent: usedPercent}, nil
}