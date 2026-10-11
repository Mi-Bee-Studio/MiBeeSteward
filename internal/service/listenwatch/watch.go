// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package listenwatch

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
)

// ProcNetPaths are the kernel's listener tables, read each cycle.
var ProcNetPaths = [2][2]string{
	{"/proc/net/tcp", "tcp"},
	{"/proc/net/tcp6", "tcp6"},
}

// Config controls the watcher (config keys listen_watch.*).
type Config struct {
	Enabled     bool
	IntervalSec int    // poll cadence; <= 0 = the 15s default
	DeviceIP    string // optional: bind events to this device's change_log entity
}

// DefaultIntervalSec is the poll cadence when config gives none.
const DefaultIntervalSec = 15

// Watcher snapshots the local LISTEN table on a cadence and emits
// change_log events for newly opened listeners. Degrade rule: on non-Linux
// (or any read failure) it logs once and stops — never crashes the server.
type Watcher struct {
	cfg     Config
	queries *db.Queries
	watcher *changedetect.Watcher
	logger  *slog.Logger

	prev     []Entry
	warned   bool
	entityID *int64 // resolved once from cfg.DeviceIP, nil = unbound
}

// NewWatcher constructs the watcher. watcher may be nil (events still
// persist; no live fan-out).
func NewWatcher(cfg Config, queries *db.Queries, watcher *changedetect.Watcher, logger *slog.Logger) *Watcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Watcher{cfg: cfg, queries: queries, watcher: watcher, logger: logger}
}

// Run blocks until ctx is done, polling on the configured cadence. The
// first snapshot establishes the baseline WITHOUT alerting (a restart must
// not replay the whole listen table as "new").
func (w *Watcher) Run(ctx context.Context) {
	interval := time.Duration(w.cfg.IntervalSec) * time.Second
	if interval <= 0 {
		interval = DefaultIntervalSec * time.Second
	}
	w.resolveEntity(ctx)
	w.prev = w.snapshot()
	w.logger.Info("listen-watch: baseline established", "listeners", len(w.prev))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cur := w.snapshot()
		for _, e := range Diff(w.prev, cur) {
			w.emit(ctx, e)
		}
		w.prev = cur
	}
}

// snapshot reads both proc tables; read failures log once and yield the
// previous set (a transient /proc hiccup must not fabricate diffs).
func (w *Watcher) snapshot() []Entry {
	var cur []Entry
	for _, p := range ProcNetPaths {
		b, err := os.ReadFile(p[0])
		if err != nil {
			if !w.warned {
				w.warned = true
				w.logger.Warn("listen-watch: cannot read the listen table; source stays off",
					"path", p[0], "error", err)
			}
			return w.prev
		}
		cur = append(cur, ParseProcNet(string(b), p[1])...)
	}
	sort.Slice(cur, func(i, j int) bool { return cur[i].Key() < cur[j].Key() })
	return cur
}

// resolveEntity binds events to a device row (best effort, once).
func (w *Watcher) resolveEntity(ctx context.Context) {
	if w.cfg.DeviceIP == "" {
		return
	}
	if d, err := w.queries.GetDeviceByIP(ctx, w.cfg.DeviceIP); err == nil {
		w.entityID = &d.ID
	} else {
		w.logger.Warn("listen-watch: device_ip does not match a device; events stay unbound",
			"device_ip", w.cfg.DeviceIP)
	}
}

// emit writes one listen_port_added change_log row and pushes it live.
func (w *Watcher) emit(ctx context.Context, e Entry) {
	after, _ := json.Marshal(map[string]any{
		"proto":       e.Proto,
		"port":        e.Port,
		"bind":        e.Addr,
		"bind_dotted": dottedBind(e),
		"source":      "listen_watch",
	})
	now := time.Now().UTC()
	row, err := w.queries.CreateChangeLog(ctx, db.CreateChangeLogParams{
		ChangeType: changedetect.ChangeTypeListenPortAdded,
		EntityType: changedetect.EntityTypeDevice,
		EntityID:   w.entityID,
		AfterData:  strPtr(string(after)),
		DetectedAt: now,
	})
	if err != nil {
		w.logger.Warn("listen-watch: write change_log failed", "error", err)
		return
	}
	w.logger.Info("listen-watch: new listening port", "proto", e.Proto, "port", e.Port)
	if w.watcher != nil {
		w.watcher.Push(row)
	}
}

// dottedBind renders the kernel hex bind address readably for the event
// payload (00000000 -> 0.0.0.0). /proc prints IPv4 as one little-endian u32
// and IPv6 as four little-endian u32 words.
func dottedBind(e Entry) string {
	switch e.Proto {
	case "tcp":
		if len(e.Addr) == 8 {
			var b [4]byte
			for i := 0; i < 4; i++ {
				b[3-i] = hexByte(e.Addr[i*2 : i*2+2])
			}
			return net.IP(b[:]).String()
		}
	case "tcp6":
		if len(e.Addr) == 32 {
			var b [16]byte
			for i := 0; i < 16; i++ {
				word := i / 4
				b[word*4+(3-(i%4))] = hexByte(e.Addr[i*2 : i*2+2])
			}
			return net.IP(b[:]).String()
		}
	}
	return e.Addr
}

func hexByte(s string) byte {
	v, _ := strconv.ParseUint(s, 16, 8)
	return byte(v)
}

func strPtr(v string) *string { return &v }
