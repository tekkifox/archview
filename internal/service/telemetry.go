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

		// Disks: sum used/total
		var diskUsed int64
		var diskTotal int64
		for _, d := range sys.Disks {
			diskUsed += int64(d.UsedBytes)
			diskTotal += int64(d.TotalBytes)
		}
		var diskUsedPtr *int64
		var diskTotalPtr *int64
		var diskPct *float64
		if diskTotal > 0 {
			diskUsedPtr = new(int64)
			diskTotalPtr = new(int64)
			*diskUsedPtr = diskUsed
			*diskTotalPtr = diskTotal
			p := (float64(diskUsed) / float64(diskTotal)) * 100.0
			r := math.Round(p*10) / 10
			diskPct = new(float64)
			*diskPct = r
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
	return m, nil
}
