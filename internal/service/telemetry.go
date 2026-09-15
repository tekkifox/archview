package service

import (
	"encoding/json"
	"math"
)

// processOverviewTelemetry builds a telemetry block from an OverviewResponse.
// The result is a map suitable for JSON encoding and attaching as `telemetry` on the
// architecture response payload.
func processOverviewTelemetry(resp OverviewResponse) map[string]any {
	telemetry := map[string]any{}

	// Build hosts array from resp.System (primary host) and optionally container nodes
	hosts := make([]map[string]any, 0)

	sys := resp.System
	if sys.Hostname != "" {
		// CPU estimate: try to estimate percent from loadAverage[0] / CPUCount
		var cpuPercent *float64
		if len(sys.LoadAverage) > 0 && sys.CPUCount > 0 {
			first := sys.LoadAverage[0]
			est := (first / float64(sys.CPUCount)) * 100.0
			// clamp and round to one decimal
			est = math.Round(est*10) / 10
			cpuPercent = new(float64)
			*cpuPercent = est
		}

		// Memory
		var memUsed *int64
		var memTotal *int64
		var memPct *float64
		if sys.Memory.TotalBytes > 0 {
			u := sys.Memory.UsedBytes
			t := sys.Memory.TotalBytes
			p := (float64(u) / float64(t)) * 100.0
			r := math.Round(p*10) / 10
			memUsed = new(int64)
			memTotal = new(int64)
			memPct = new(float64)
			*memUsed = u
			*memTotal = t
			*memPct = r
		}

		// Disks: prefer the '/' mount point only. If not present, omit disk telemetry.
		var diskUsedPtr *int64
		var diskTotalPtr *int64
		var diskPct *float64
		for _, d := range sys.Disks {
			if d.MountPoint == "/" {
				du := int64(d.UsedBytes)
				dt := int64(d.TotalBytes)
				diskUsedPtr = new(int64)
				diskTotalPtr = new(int64)
				*diskUsedPtr = du
				*diskTotalPtr = dt
				if dt > 0 {
					p := (float64(du) / float64(dt)) * 100.0
					r := math.Round(p*10) / 10
					diskPct = new(float64)
					*diskPct = r
				}
				break
			}
		}

		// Network: sum received/sent
		var rxTotal uint64
		var txTotal uint64
		for _, n := range sys.Network {
			rxTotal += n.Received
			txTotal += n.Sent
		}

		host := map[string]any{
			"name":        sys.Hostname,
			"os":          sys.OS,
			"kernel":      sys.Kernel,
			"cpuCount":    sys.CPUCount,
			"loadAverage": sys.LoadAverage,
		}

		if cpuPercent != nil {
			host["cpu"] = *cpuPercent
		}
        if memUsed != nil && memTotal != nil {
            host["memoryUsedBytes"] = *memUsed
            host["memoryTotalBytes"] = *memTotal
            host["memoryPercent"] = *memPct
            // include swap stats when available
            host["swapTotalBytes"] = sys.Memory.SwapTotalBytes
            host["swapFreeBytes"] = sys.Memory.SwapFreeBytes
        }
		if diskUsedPtr != nil && diskTotalPtr != nil {
			host["diskUsedBytes"] = *diskUsedPtr
			host["diskTotalBytes"] = *diskTotalPtr
			host["diskPercent"] = *diskPct
		}
        if rxTotal > 0 || txTotal > 0 {
            host["networkRxBytes"] = rxTotal
            host["networkTxBytes"] = txTotal
        }
        // process count
        if sys.Processes > 0 {
            host["processes"] = sys.Processes
        }

		hosts = append(hosts, host)
	}

	// Aggregate metrics across hosts (we currently have only one primary host)
	metrics := map[string]any{}
	if len(hosts) > 0 {
		h := hosts[0]
		if v, ok := h["cpu"].(float64); ok {
			metrics["cpuAvg"] = v
		}
		if v, ok := h["memoryUsedBytes"].(int64); ok {
			metrics["memoryUsedBytes"] = v
		}
		if v, ok := h["memoryTotalBytes"].(int64); ok {
			metrics["memoryTotalBytes"] = v
		}
        if v, ok := h["memoryPercent"].(float64); ok {
            metrics["memoryPercent"] = v
        }
        if v, ok := h["swapTotalBytes"].(int64); ok {
            metrics["swapTotalBytes"] = v
        }
        if v, ok := h["swapFreeBytes"].(int64); ok {
            metrics["swapFreeBytes"] = v
            // compute swap percent when both values present
            if sTot, ok2 := metrics["swapTotalBytes"].(int64); ok2 && sTot > 0 {
                sUsed := sTot - v
                sp := (float64(sUsed) / float64(sTot)) * 100.0
                metrics["swapPercent"] = math.Round(sp*10) / 10
            }
        }
		if v, ok := h["diskUsedBytes"].(int64); ok {
			metrics["diskUsedBytes"] = v
		}
		if v, ok := h["diskTotalBytes"].(int64); ok {
			metrics["diskTotalBytes"] = v
		}
		if v, ok := h["diskPercent"].(float64); ok {
			metrics["diskPercent"] = v
		}
		if v, ok := h["networkRxBytes"].(uint64); ok {
			metrics["networkRxMB"] = float64(v) / 1024.0 / 1024.0
		}
		if v, ok := h["networkTxBytes"].(uint64); ok {
			metrics["networkTxMB"] = float64(v) / 1024.0 / 1024.0
		}
		if la, ok := h["loadAverage"].([]float64); ok && len(la) > 0 {
			metrics["loadAvg"] = la[0]
		}
        metrics["hostCount"] = len(hosts)
        // process count aggregate (primary host)
        if v, ok := h["processes"].(int); ok {
            metrics["processCount"] = v
        } else if v64, ok := h["processes"].(int64); ok {
            metrics["processCount"] = int(v64)
        } else if vf, ok := h["processes"].(float64); ok {
            metrics["processCount"] = int(vf)
        }
		if hosts[0]["os"] != nil {
			metrics["topOS"] = hosts[0]["os"]
		}
	}

	telemetry["hosts"] = hosts
	telemetry["metrics"] = metrics
	return telemetry
}

// attachTelemetry merges telemetry into the response map and returns bytes-ready object
func attachTelemetryToOverview(resp OverviewResponse) (map[string]any, error) {
	// marshal OverviewResponse then unmarshal into map[string]any to preserve structure
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
    telemetry := processOverviewTelemetry(resp)
    m["telemetry"] = telemetry
    // Remove the raw System block to force consumers to use telemetry instead
    delete(m, "system")
    return m, nil
}
