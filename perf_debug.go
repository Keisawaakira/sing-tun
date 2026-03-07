package tun

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/sing/common/logger"
)

const tunPerfReportInterval = 2 * time.Second

var tunPerfDebugEnabled = func() bool {
	value, ok := os.LookupEnv("SING_TUN_PERF_DEBUG")
	if !ok {
		return false
	}
	if value == "" {
		return true
	}
	enabled, err := strconv.ParseBool(value)
	if err == nil {
		return enabled
	}
	return value != "0"
}()

type tunPerfDebug struct {
	logger logger.Logger
	label  string

	lastReport atomic.Int64

	readPackets  atomic.Uint64
	readBytes    atomic.Uint64
	readNanos    atomic.Int64
	readErrors   atomic.Uint64

	writePackets  atomic.Uint64
	writeBytes    atomic.Uint64
	writeNanos    atomic.Int64
	writeErrors   atomic.Uint64
	writeOverflow atomic.Uint64

	spinCalls atomic.Uint64
	spinNanos atomic.Int64

	waitCalls atomic.Uint64
	waitNanos atomic.Int64
}

func newTunPerfDebug(log logger.Logger, label string) *tunPerfDebug {
	if !tunPerfDebugEnabled {
		return nil
	}
	if log == nil {
		return nil
	}
	if !strings.HasPrefix(label, "wintun:") {
		return nil
	}
	debug := &tunPerfDebug{
		logger: log,
		label:  label,
	}
	debug.lastReport.Store(time.Now().UnixNano())
	debug.logger.Warn("tun-perf enabled: ", label, " mode=hybrid-spin")
	return debug
}

func (d *tunPerfDebug) setLabel(label string) {
	if d == nil {
		return
	}
	d.label = label
}

func (d *tunPerfDebug) observeRead(duration time.Duration, bytes int, err error) {
	if d == nil {
		return
	}
	if err != nil {
		d.readErrors.Add(1)
	} else {
		d.readPackets.Add(1)
		d.readBytes.Add(uint64(bytes))
		d.readNanos.Add(duration.Nanoseconds())
	}
	d.maybeReport()
}

func (d *tunPerfDebug) observeShortPacket() {
}

func (d *tunPerfDebug) observeProcess(duration time.Duration, writeBack bool) {
}

func (d *tunPerfDebug) observeWrite(duration time.Duration, bytes int, err error) {
	if d == nil {
		return
	}
	if err != nil {
		d.writeErrors.Add(1)
	} else {
		d.writePackets.Add(1)
		d.writeBytes.Add(uint64(bytes))
		d.writeNanos.Add(duration.Nanoseconds())
	}
	d.maybeReport()
}

func (d *tunPerfDebug) observeSpin(duration time.Duration) {
	if d == nil {
		return
	}
	d.spinCalls.Add(1)
	d.spinNanos.Add(duration.Nanoseconds())
	d.maybeReport()
}

func (d *tunPerfDebug) observeEmpty(spun bool, waited bool) {
	if d == nil || !waited {
		return
	}
	d.waitCalls.Add(1)
	d.maybeReport()
}

func (d *tunPerfDebug) observeWait(duration time.Duration) {
	if d == nil {
		return
	}
	d.waitCalls.Add(1)
	d.waitNanos.Add(duration.Nanoseconds())
	d.maybeReport()
}

func (d *tunPerfDebug) observeWriteOverflow() {
	if d == nil {
		return
	}
	d.writeOverflow.Add(1)
	d.maybeReport()
}

func (d *tunPerfDebug) maybeReport() {
	if d == nil {
		return
	}
	now := time.Now().UnixNano()
	last := d.lastReport.Load()
	if time.Duration(now-last) < tunPerfReportInterval {
		return
	}
	if !d.lastReport.CompareAndSwap(last, now) {
		return
	}
	interval := time.Duration(now - last)
	readPackets := d.readPackets.Swap(0)
	readBytes := d.readBytes.Swap(0)
	readNanos := d.readNanos.Swap(0)
	readErrors := d.readErrors.Swap(0)
	writePackets := d.writePackets.Swap(0)
	writeBytes := d.writeBytes.Swap(0)
	writeNanos := d.writeNanos.Swap(0)
	writeErrors := d.writeErrors.Swap(0)
	writeOverflow := d.writeOverflow.Swap(0)
	spinCalls := d.spinCalls.Swap(0)
	spinNanos := d.spinNanos.Swap(0)
	waitCalls := d.waitCalls.Swap(0)
	waitNanos := d.waitNanos.Swap(0)
	if readPackets == 0 && writePackets == 0 && readErrors == 0 && writeErrors == 0 && writeOverflow == 0 && waitCalls == 0 && spinCalls == 0 {
		return
	}
	d.logger.Warn(
		"tun-perf[", d.label, "] ",
		"interval=", interval,
		" read_pkts=", readPackets,
		" read_mbps=", formatTunPerfMbps(readBytes, interval),
		" read_avg_us=", formatTunPerfAvgMicros(readNanos, readPackets),
		" spins=", spinCalls,
		" spin_avg_us=", formatTunPerfAvgMicros(spinNanos, spinCalls),
		" spin_pct=", formatTunPerfPercent(spinNanos, interval),
		" waits=", waitCalls,
		" wait_avg_us=", formatTunPerfAvgMicros(waitNanos, waitCalls),
		" wait_pct=", formatTunPerfPercent(waitNanos, interval),
		" pkts_per_wait=", formatTunPerfPktsPerWait(readPackets, waitCalls),
		" write_pkts=", writePackets,
		" write_mbps=", formatTunPerfMbps(writeBytes, interval),
		" write_avg_us=", formatTunPerfAvgMicros(writeNanos, writePackets),
		" overflow=", writeOverflow,
		" read_err=", readErrors,
		" write_err=", writeErrors,
	)
}

func formatTunPerfMbps(bytes uint64, interval time.Duration) string {
	if bytes == 0 || interval <= 0 {
		return "0.0"
	}
	mbps := float64(bytes*8) / interval.Seconds() / 1000 / 1000
	return strconv.FormatFloat(mbps, 'f', 1, 64)
}

func formatTunPerfAvgMicros(totalNanos int64, count uint64) string {
	if totalNanos == 0 || count == 0 {
		return "0.0"
	}
	avg := float64(totalNanos) / float64(count) / 1000
	return strconv.FormatFloat(avg, 'f', 1, 64)
}

func formatTunPerfPercent(totalNanos int64, interval time.Duration) string {
	if totalNanos == 0 || interval <= 0 {
		return "0.0"
	}
	share := float64(totalNanos) / float64(interval.Nanoseconds()) * 100
	return strconv.FormatFloat(share, 'f', 1, 64)
}

func formatTunPerfPktsPerWait(readPackets uint64, waitCalls uint64) string {
	if waitCalls == 0 {
		if readPackets == 0 {
			return "0.0"
		}
		return "inf"
	}
	ratio := float64(readPackets) / float64(waitCalls)
	return strconv.FormatFloat(ratio, 'f', 1, 64)
}
