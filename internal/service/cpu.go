package service

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// cpuSampleInterval is how far apart the two <HOST_PROC>/stat readings are
// taken. A single reading is an average since boot, so the gap between two
// readings is what describes current utilisation.
const cpuSampleInterval = 250 * time.Millisecond

// cpuSample is the aggregate CPU time from the "cpu" line of /proc/stat,
// in clock ticks (jiffies). busy is everything except idle and iowait.
type cpuSample struct {
	busy  uint64
	total uint64
}

// readCPUPercent reports host CPU utilisation as a percentage of all CPU
// time, rounded to one decimal and clamped to 0-100. It returns nil when
// either reading of <HOST_PROC>/stat fails or no CPU time elapsed between
// them, so callers omit the figure rather than publish a fabricated zero.
func readCPUPercent(procRoot string) *float64 {
	return measureCPUPercent(procRoot, cpuSampleInterval, time.Sleep)
}

// measureCPUPercent takes two cpuSample readings interval apart. sleep is a
// parameter so tests can rewrite the fixture between readings without waiting.
func measureCPUPercent(procRoot string, interval time.Duration, sleep func(time.Duration)) *float64 {
	first, err := readCPUSample(procRoot)
	if err != nil {
		return nil
	}
	sleep(interval)
	second, err := readCPUSample(procRoot)
	if err != nil {
		return nil
	}
	return cpuPercentBetween(first, second)
}

// cpuPercentBetween converts two aggregate readings into the busy percentage
// of the CPU time elapsed between them. It returns nil when no total CPU time
// elapsed (a zero delta) or the counters went backwards.
func cpuPercentBetween(prev, next cpuSample) *float64 {
	if next.total <= prev.total || next.busy < prev.busy {
		return nil
	}
	total := next.total - prev.total
	busy := next.busy - prev.busy
	percent := float64(busy) / float64(total) * 100.0
	percent = math.Round(percent*10) / 10
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return &percent
}

// readCPUSample reads the aggregate "cpu" line from <HOST_PROC>/stat.
func readCPUSample(procRoot string) (cpuSample, error) {
	file, err := os.Open(filepath.Join(procRoot, "stat"))
	if err != nil {
		return cpuSample{}, err
	}
	defer file.Close()
	return parseCPUSample(file)
}

// parseCPUSample parses the aggregate "cpu" line:
//
//	cpu user nice system idle iowait irq softirq steal guest guest_nice
//
// Busy is every field except idle and iowait; total is the sum of all fields.
func parseCPUSample(r io.Reader) (cpuSample, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		if len(fields) < 6 {
			return cpuSample{}, fmt.Errorf("stat cpu line has %d fields, want at least 6", len(fields))
		}
		var total, idle uint64
		for i, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return cpuSample{}, fmt.Errorf("stat cpu field %q: %w", field, err)
			}
			total += value
			if i == 3 || i == 4 { // idle, iowait
				idle += value
			}
		}
		if total == 0 {
			return cpuSample{}, fmt.Errorf("stat cpu counters are all zero")
		}
		return cpuSample{busy: total - idle, total: total}, nil
	}
	if err := scanner.Err(); err != nil {
		return cpuSample{}, err
	}
	return cpuSample{}, fmt.Errorf("stat has no aggregate cpu line")
}
