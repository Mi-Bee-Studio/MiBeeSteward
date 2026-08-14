// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package routes

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/authz/scoperesolver"
	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/config"
	"mibee-steward/internal/crypto"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/notification"
	scannerv2cleanup "mibee-steward/internal/service/scannerv2/cleanup"
	scannerv2configbackup "mibee-steward/internal/service/scannerv2/configbackup"
	credresolver "mibee-steward/internal/service/scannerv2/credresolver"
	scannerv2discovery "mibee-steward/internal/service/scannerv2/discovery"
	scannerv2ebpf "mibee-steward/internal/service/scannerv2/ebpf"
	scannerv2engine "mibee-steward/internal/service/scannerv2/engine"
	scannerv2probe "mibee-steward/internal/service/scannerv2/probe"
	scannerv2reconcile "mibee-steward/internal/service/scannerv2/reconcile"
	scannerv2runner "mibee-steward/internal/service/scannerv2/runner"
	scannerv2scheduler "mibee-steward/internal/service/scannerv2/scheduler"
	"mibee-steward/internal/service/scannerv2/sshcred"
	scannerv2task "mibee-steward/internal/service/scannerv2/taskservice"
)

// NewRouter creates and returns the main HTTP router with all routes registered.
// It requires the database connection and configuration to set up auth and user routes.
func NewRouter(dbConn *sql.DB, cfg *config.Config) (http.Handler, *service.HeartbeatService, func()) {
	r := chi.NewMux()

	// Initialize JWT auth
	middleware.SetJWTAuth(cfg.Auth.JWTSecret)
	// Initialize token blacklist for JWT revocation
	tokenBlacklist := service.NewTokenBlacklist()
	tokenBlacklist.StartCleanup()
	middleware.SetTokenBlacklist(tokenBlacklist)

	// Parse token expiry, default to 24h
	expiry := 24 * time.Hour
	if cfg.Auth.TokenExpiry != "" {
		if d, err := time.ParseDuration(cfg.Auth.TokenExpiry); err == nil {
			expiry = d
		}
	}

	// User service and handler
	userSvc := service.NewUserService(dbConn, cfg.Auth.JWTSecret, expiry)
	// Audit logging
	auditRepo := service.NewAuditRepository(dbConn)

	userHandler := handler.NewUserHandler(userSvc, cfg, auditRepo, tokenBlacklist)

	// TOTP service and handler
	totpSvc := service.NewTOTPService(dbConn, auditRepo)
	userSvc.SetTOTPService(totpSvc)
	totpHandler := handler.NewTOTPHandler(totpSvc, userSvc, cfg, auditRepo)

	// Audit service and handler
	auditSvc := service.NewAuditService(dbConn)
	auditHandler := handler.NewAuditHandler(auditSvc)

	// Batch service and handler
	batchSvc := service.NewBatchService(dbConn, auditRepo)
	batchHandler := handler.NewBatchHandler(batchSvc)

	// NOTE: export handler is constructed after the heartbeat store opens below,
	// so heartbeat-results export can read from the dedicated store. See comment there.
	// Rate limiters
	loginRate := cfg.RateLimit.LoginPerMinute
	if loginRate <= 0 {
		loginRate = 10
	}
	globalRate := cfg.RateLimit.GlobalPerMinute
	if globalRate <= 0 {
		globalRate = 100
	}
	loginLimiter := middleware.NewRateLimiter(loginRate/60.0, int(loginRate))
	globalLimiter := middleware.NewRateLimiter(globalRate/60.0, int(globalRate))
	scanRate := cfg.RateLimit.ScanPerMinute
	if scanRate <= 0 {
		scanRate = 10
	}
	scanLimiter := middleware.NewScanRateLimiter(int(scanRate))

	// Middleware chain: RequestID → RealIP → Logging → Metrics → Recoverer → SecurityHeaders
	r.Use(chimw.RequestID)
	// RealIP is trusted-proxy-aware: X-Forwarded-For is honored ONLY when the
	// TCP peer is in server.trusted_proxies (default empty = trust no proxy,
	// use the TCP peer as the client — safe for direct exposure). Deploy behind
	// nginx and set trusted_proxies to the proxy's source range (#133).
	r.Use(middleware.RealIP(middleware.ParseCIDRs(cfg.Server.TrustedProxies)))
	r.Use(middleware.Logging)
	r.Use(middleware.Metrics)
	r.Use(chimw.Recoverer)
	r.Use(middleware.CORS(cfg.CORS.AllowedOrigins))
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.CSRF)
	r.Use(globalLimiter.Middleware)

	// API routes (public: health, login, metrics, sd)
	r.Get("/api/v1/health", handler.HealthHandler(dbConn))

	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Use(loginLimiter.Middleware)
		r.Mount("/", userHandler.Routes())
		// 2FA routes (public verify + protected setup/enable/disable/status)
		r.Route("/2fa", func(r chi.Router) {
			r.Post("/verify", totpHandler.Verify)
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireAuth)
				r.Post("/setup", totpHandler.Setup)
				r.Post("/enable", totpHandler.Enable)
				r.Post("/disable", totpHandler.Disable)
				r.Get("/status", totpHandler.Status)
			})
		})
	})

	// Object-level network scope resolver (#138 Phase 2). Resolves a user's
	// granted network set (closed mode) or Global (admin / open mode). Consumed
	// by NetworkScope (injects scope into context), the device query paths, and
	// the network-grant management handler (Phase 3, for cache invalidation).
	scopeResolver := scoperesolver.New(dbConn, domain.ScopeMode(cfg.RBAC.ScopeDefault))
	// Network-grant management handler (#138 Phase 3): admin assigns/removes a
	// user's network scope. CapUserManage = admin-only. The handler invalidates
	// the scope resolver cache per affected user so changes apply immediately.
	networkGrantHandler := handler.NewNetworkGrantHandler(dbConn, scopeResolver)

	// User management — admin-only (#138 CapUserManage; admin is the only role
	// that holds it, so this preserves the prior RequireAdmin semantics while
	// expressing the gate through the capability matrix).
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapUserManage))
		r.Get("/", userHandler.ListUsers)
		r.Post("/batch-delete", batchHandler.BatchDeleteUsers)
		r.Post("/{id}/reset-password", userHandler.AdminResetPassword)
		// Per-user network grants (#138 Phase 3) — list the networks a user is
		// scoped to (closed mode). The create/delete surface is /network-grants.
		r.Get("/{id}/network-grants", networkGrantHandler.ListByUser)
	})

	r.Route("/api/v1/network-grants", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapUserManage))
		r.Get("/", networkGrantHandler.List)
		r.Post("/", networkGrantHandler.Create)
		r.Delete("/{id}", networkGrantHandler.Delete)
	})
	// Heartbeat service + its dedicated time-series store. heartbeat_results
	// lives in a separate SQLite file (data/heartbeat.db) so its high write
	// volume (~270k rows/day) doesn't contend with the main DB's CRUD writers.
	heartbeatDBPath := heartbeatDBPathFor(cfg)
	hbStore, err := service.OpenHeartbeatStore(heartbeatDBPath)
	if err != nil {
		slog.Error("failed to open heartbeat store", "path", heartbeatDBPath, "error", err)
		os.Exit(1)
	}
	heartbeatSvc := service.NewHeartbeatService(dbConn, hbStore, cfg)

	// Export handler — bound to the main DB for devices/audit, and to the
	// dedicated heartbeat store for heartbeat_results (which lives in
	// heartbeat.db after the time-series split; the main DB's copy is stale).
	exportHandler := handler.NewExportHandler(service.NewExportService(db.New(dbConn), hbStore.Queries(), dbConn))

	// Device routes
	deviceRepo := service.NewDeviceRepository(dbConn)
	deviceSvc := service.NewDeviceService(deviceRepo, heartbeatSvc)
	deviceHandler := handler.NewDeviceHandler(deviceSvc)
	r.Route("/api/v1/devices", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceRead))
			r.Use(middleware.NetworkScope(scopeResolver))
			r.Get("/export", exportHandler.ExportDevices)
			r.Get("/", deviceHandler.List)
			r.Get("/stats", deviceHandler.GetStats)
			r.With(middleware.ValidateDeviceScope(dbConn)).Get("/{id}", deviceHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceWrite))
			r.Use(middleware.NetworkScope(scopeResolver))
			r.Post("/", deviceHandler.Create)
			r.With(middleware.ValidateDeviceScope(dbConn)).Put("/{id}", deviceHandler.Update)
			r.With(middleware.ValidateDeviceScope(dbConn)).Delete("/{id}", deviceHandler.Delete)
			r.Post("/batch-delete", batchHandler.BatchDeleteDevices)
			r.Post("/batch-update-status", batchHandler.BatchUpdateDeviceStatus)
		})
	})
	// Scanner routes (v2 engine)
	scanQueries := db.New(dbConn)
	// Wire the DB querier for agent-token verification (RequireAgentToken). Done
	// here so the ingestion routes (registered below) can authenticate agents.
	middleware.SetAgentQueries(scanQueries)

	// Network registry — feeds the device-list + change-history network filters
	// and the Networks admin page. Read (List) is any logged-in user; create/
	// update/delete require CapNetworkManage (admin-only capability).
	networkHandler := handler.NewNetworkHandler(scanQueries, dbConn)
	r.Route("/api/v1/networks", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapNetworkRead))
		r.Get("/", networkHandler.List)
		r.With(middleware.RequireCapability(domain.CapNetworkManage)).Post("/", networkHandler.Create)
		r.With(middleware.RequireCapability(domain.CapNetworkManage)).Put("/{id}", networkHandler.Update)
		r.With(middleware.RequireCapability(domain.CapNetworkManage)).Delete("/{id}", networkHandler.Delete)
	})

	// L2 topology — neighbors per device (detail page) + the whole-network
	// topology graph (nodes + edges). Read-only; any logged-in user.
	neighborHandler := handler.NewNeighborHandler(scanQueries)
	topologyHandler := handler.NewTopologyHandler(scanQueries)
	// TLS certificates per device (detail page TLS sub-panel + Modal). Read-only;
	// any logged-in user. Same *db.Queries as the neighbors handler.
	tlsCertHandler := handler.NewTLSCertHandler(scanQueries)
	// Versioned running-config history per device (detail page "Config History"
	// tab, #137). Read-only; any logged-in user. The write path is the background
	// configbackup.Service; this handler only reads device_configs.
	deviceConfigHandler := handler.NewDeviceConfigHandler(scanQueries)

	// Resolve this instance's network identity (networks.id) so discovered
	// devices can be tagged with their origin. Done here (not in migrations)
	// because the value comes from config `network.name`.
	networkID := resolveNetworkID(dbConn, cfg)

	// Construct the v2 engine: probes/classifiers/handlers + persistence + eBPF observer.
	// Port spec: prefer the configured default_ports (config.yaml
	// scanner.pipeline_defaults.default_ports) and fall back to the v2 default
	// set if unset. The default set covers web/admin + cameras + prometheus +
	// databases + mail + remote-access so the common inventory cases are caught
	// out of the box.
	scannerPortSpec := cfg.Scanner.PipelineDefaults.DefaultPorts
	if scannerPortSpec == "" {
		scannerPortSpec = config.DefaultScanPortSpec
	}

	// SNMPv3 credential resolver (issue #135). Build the AES-GCM cipher from
	// security.master_key, then a resolver that decrypts credential rows on
	// demand. When the master key is unset/invalid, credResolver is nil and the
	// engine falls back to the v1/v2c community path (existing deployments keep
	// working). The handler layer also gets these for the credential CRUD API.
	credCipher, credResolver := buildCredentialCipher(dbConn, cfg)

	v2Engine, engineErr := scannerv2engine.NewEngine(dbConn, scannerv2engine.Config{
		PortSpec:           scannerPortSpec,
		MaxConcurrentHosts: cfg.Scanner.MaxConcurrentHosts,
		MaxConcurrentScans: cfg.Scanner.MaxConcurrentScans,
		PerHostTimeout:     time.Duration(cfg.Scanner.DefaultTimeout) * time.Second,
		PerProbeTimeout:    time.Duration(cfg.Scanner.PerProbeTimeout) * time.Second,
		PersistRawEvidence: cfg.Scanner.PersistRawEvidence,
		OUIPath:            cfg.Scanner.OUIPath,
		FingerprintPath:    cfg.Scanner.FingerprintPath,
		SNMPCommunity:      cfg.Scanner.SNMPCommunity,
		CredResolver:       credResolver,
		RouterARP: scannerv2probe.RouterARPConfig{
			Routers:   cfg.Scanner.RouterARP.Routers,
			Community: routerCommunity(cfg.Scanner),
			Timeout:   time.Duration(routerTimeout(cfg.Scanner)) * time.Second,
		},
		RDNS: scannerv2probe.RDNSConfig{
			DNSServers: cfg.Scanner.RDNS.DNSServers,
			Timeout:    time.Duration(rdnsTimeout(cfg.Scanner)) * time.Second,
		},
		MDNS: scannerv2probe.MDNSConfig{
			UnicastQueries: cfg.Scanner.MDNS.UnicastQueries,
		},
		HeartbeatInterval: cfg.Heartbeat.DefaultInterval,
		HeartbeatTimeout:  cfg.Heartbeat.Timeout,
		NetworkID:         networkID,
		EBPF: scannerv2ebpf.Config{
			Enabled:    cfg.Scanner.EBPF.Enabled,
			Interfaces: cfg.Scanner.EBPF.Interfaces,
		},
	}, slog.Default())
	if engineErr != nil {
		slog.Error("failed to init scannerv2 engine", "error", engineErr)
	}

	// Runner: connects the engine to run/result persistence + the device bridge.
	scanRunner := scannerv2runner.New(v2Engine, scanQueries, dbConn, heartbeatSvc, networkID, slog.Default())
	scanRunner.SetRepo(v2Engine.Repository)                // device-identity upsert (ResolveDeviceIdentity / ApplyDeviceIdentity)
	scanRunner.SetLostThreshold(cfg.Scanner.LostThreshold) // scanner.lost_threshold (default 2; <=0 keeps default)

	// Change detection (Phase 3): the center records device_added/changed/lost
	// events to change_log + pushes in-process Watcher subscribers. The agent
	// does NOT set this (change detection is a center concern; agents only
	// forward raw HostReports). The watcher is the foundation for a future
	// /watch SSE endpoint (Step 4 surfaces a query API on top of change_log).
	changeWatcher := changedetect.NewWatcher(slog.Default())
	// Cooldown dedup: a device_changed/device_recovered for the same device
	// within 15 minutes is suppressed (the devices row already reflects the
	// current state; change_log records transitions, not every observation).
	// device_added/device_lost are never throttled. See changedetect.DBRecorder.
	changeRecorder := changedetect.NewDBRecorder(scanQueries, changeWatcher, 15*time.Minute, slog.Default())
	scanRunner.SetChangeRecorder(changeRecorder)

	// Lease sweeper: background expiration of agent-managed devices whose
	// snapshots have gone stale (the agent stopped reporting them). This
	// replaces the per-report DetectLost that used to run on every agent POST
	// (O(whole network) each time). Center-only; scope is agent networks
	// (networks.agent_id non-empty) — the center's own network keeps using
	// the local-scan DetectLost path + heartbeat. Stopped in the cleanup
	// closure below before db.Close().
	leaseTTL := parseDurationOrDefault(cfg.Scanner.AgentLeaseTTL, 5*time.Minute)
	leaseSweepInterval := parseDurationOrDefault(cfg.Scanner.LeaseSweepInterval, 60*time.Second)
	leaseSweepCtx, leaseSweepCancel := context.WithCancel(context.Background())
	leaseSweeper := scannerv2runner.NewLeaseSweeper(scanRunner, leaseSweepInterval, leaseTTL, slog.Default())
	leaseSweeper.Start(leaseSweepCtx)

	// Network-attribution reconciliation (issue #19 Layer 3): a slow background
	// audit that detects devices whose IP has drifted outside their stamped
	// network's CIDR. This is the bottom-line defense — it catches drift the
	// Layer 1 (dispatch) + Layer 2 (ingestion) boundary checks miss (e.g. a
	// network without a cidr, or a future code path that bypasses them).
	// Detect-and-surface only; correction stays a human decision (Layer 4).
	// Center-only; stopped in the cleanup closure below before db.Close().
	reconcileInterval := parseDurationOrDefault(cfg.Scanner.ReconcileInterval, time.Hour)
	reconcileCtx, reconcileCancel := context.WithCancel(context.Background())
	reconciler := scannerv2reconcile.New(dbConn, reconcileInterval, prometheus.DefaultRegisterer, slog.Default())
	reconciler.Start(reconcileCtx)

	// Passive discovery service: a long-running, near-zero-traffic watcher that
	// spots newly-appeared hosts between scheduled scans by diffing router/local
	// ARP tables and passively listening for mDNS/SSDP. New hosts are fed through
	// the SAME device bridge as scans (so they get device_added events + heartbeat
	// seeding). Sources are enabled per config; the coordinator is always
	// constructed so the config surface is stable, but its goroutine + sources
	// only start when scanner.discovery.enabled is true. Stopped in the cleanup
	// closure below before db.Close().
	discSvc := scannerv2discovery.New(
		scannerv2discovery.Config{
			Interval:        time.Duration(cfg.Scanner.Discovery.Interval) * time.Second,
			TriggerIdentify: cfg.Scanner.Discovery.TriggerIdentify,
		},
		scannerv2discovery.SinkAdapter{Runner: scanRunner},
		scannerv2discovery.IdentifierAdapter(v2Engine),
		dbConn, networkID, slog.Default(),
	)
	var discCancel context.CancelFunc
	// discSvcForStatus carries the discovery service to the status endpoint.
	// nil when the service was never started (discovery disabled) — the handler
	// then reports enabled=false. Declared here so the route registration below
	// (outside the if-block) can reference it.
	var discSvcForStatus *scannerv2discovery.Service
	if cfg.Scanner.Discovery.Enabled {
		discSvcForStatus = discSvc
		discCtx, cancel := context.WithCancel(context.Background())
		discCancel = cancel
		discSvc.Start(discCtx)
		interval := time.Duration(cfg.Scanner.Discovery.Interval) * time.Second
		if interval <= 0 {
			interval = 60 * time.Second
		}
		var activeSources []string
		// router_arp exists for the case where the center is NOT on the gateway
		// — it walks a router's SNMP ARP table from across the subnet to recover
		// cross-subnet MACs the center can't see at L2. When the center runs ON
		// the gateway (form C, deploy/openwrt/) the router's OWN sources cover the
		// same hosts authoritatively (and more — dhcp_leases, conntrack, hostapd),
		// so router_arp is redundant and just adds SNMP traffic to the router. The
		// same applies to a router-resident agent (form B) reporting into this
		// center for that network: the agent's own arp_cache/dhcp_leases are
		// upstream and router_arp is duplicative. Warn when both are on so the
		// operator knows to disable router_arp; we don't force-disable because the
		// operator may have a reason (e.g. transitional overlap during migration).
		if cfg.Scanner.Discovery.RouterARP.Enabled && routerResidentSourcesOn(cfg.Scanner.Discovery) {
			slog.Warn("discovery: router_arp is enabled alongside router-resident sources " +
				"(arp_cache/dhcp_leases/conntrack) — router_arp is redundant when the center " +
				"(or an agent) runs on the gateway. Disable scanner.discovery.router_arp " +
				"to avoid the redundant SNMP walk.")
		}
		// router_arp: the widest-coverage source for a NON-router-resident center.
		// One SNMP Walk per router per interval; no-op when no routers configured.
		if cfg.Scanner.Discovery.RouterARP.Enabled {
			routerARPSrc := scannerv2discovery.NewRouterARPSource(
				cfg.Scanner.RouterARP.Routers,
				routerCommunity(cfg.Scanner),
				time.Duration(routerTimeout(cfg.Scanner))*time.Second,
				interval, discSvc, slog.Default(),
			)
			routerARPSrc.Start(discCtx)
			activeSources = append(activeSources, "router_arp")
		}
		// arp_cache: free byproduct of normal operation (reads /proc/net/arp).
		if cfg.Scanner.Discovery.ARPCache.Enabled {
			arpCacheSrc := scannerv2discovery.NewARPCacheSource(interval, discSvc, slog.Default())
			arpCacheSrc.Start(discCtx)
			activeSources = append(activeSources, "arp_cache")
		}
		// multicast: passive mDNS/SSDP listener (zero outbound traffic).
		if cfg.Scanner.Discovery.Multicast.Enabled {
			mcastSrc := scannerv2discovery.NewMulticastSource(discSvc, slog.Default())
			mcastSrc.Start(discCtx)
			activeSources = append(activeSources, "multicast")
		}
		// dhcp_leases: Tier-1 router signal — the DHCP authority's hostname↔MAC↔IP
		// map. No-op on a host that isn't the LAN's DHCP server (file absent).
		if cfg.Scanner.Discovery.DHCPLeases.Enabled {
			dhcpSrc := scannerv2discovery.NewDHCPLeasesSource(interval, "", discSvc, slog.Default())
			dhcpSrc.Start(discCtx)
			activeSources = append(activeSources, "dhcp_leases")
		}
		// conntrack: Tier-1 router signal — the NAT choke point's "who is talking
		// RIGHT NOW" view. Filters to the center's own LAN CIDR.
		if cfg.Scanner.Discovery.Conntrack.Enabled {
			conntrackSrc := scannerv2discovery.NewConntrackSource(cfg.Network.CIDR, interval, discSvc, slog.Default())
			conntrackSrc.Start(discCtx)
			activeSources = append(activeSources, "conntrack")
		}
		// hostapd: Tier-1 router/AP signal — WiFi STA associations (signal dBm,
		// connect time, SSID). hostapd ctrl socket first, iw station dump fallback.
		if cfg.Scanner.Discovery.Hostapd.Enabled {
			hostapdSrc := scannerv2discovery.NewHostapdSource(cfg.Scanner.Discovery.Hostapd.Interfaces, interval, discSvc, slog.Default())
			hostapdSrc.Start(discCtx)
			activeSources = append(activeSources, "hostapd")
		}
		// dns_log: Tier-1 router signal — tails the dnsmasq query log for passive
		// DNS fingerprinting (devices that block inbound probes still do DNS).
		if cfg.Scanner.Discovery.DNSLog.Enabled {
			dnsLogSrc := scannerv2discovery.NewDNSLogSource(interval, cfg.Scanner.Discovery.DNSLog.Path, discSvc, slog.Default())
			dnsLogSrc.Start(discCtx)
			activeSources = append(activeSources, "dns_log")
		}
		// arp_scan: active ARP who-has sweep of the whole network CIDR. The only
		// source that covers the entire broadcast domain with NO router access
		// (every host must answer ARP — even firewalled ones). Needs the
		// WITH_ARPSCAN build tag + CAP_NET_RAW; NewARPScanSource returns nil in the
		// default build or when raw sockets are unavailable (no CAP_NET_RAW), so the
		// nil guard skips it silently in those cases.
		if cfg.Scanner.Discovery.ARPScan.Enabled {
			if arpScanSrc := scannerv2discovery.NewARPScanSource(
				cfg.Network.CIDR, interval, cfg.Scanner.ARPScan.Interface,
				discSvc, slog.Default(),
			); arpScanSrc != nil {
				arpScanSrc.Start(discCtx)
				activeSources = append(activeSources, "arp_scan")
			}
		}
		// lldp_frame: passive LLDPDU frame listener (ethertype 0x88cc). Only
		// available in WITH_LLDP builds (needs CAP_NET_RAW); NewLLDPFrameSource
		// returns nil in the default build, so this is a no-op there. Wiring the
		// neighbor-edge sink needs a MAC-keyed device resolver (RecordNeighbors
		// is IP-keyed); deferred until that lands. The host-event path works.
		if lldpSrc := scannerv2discovery.NewLLDPFrameSource(
			cfg.Scanner.Discovery.LLDPInterfaces, discSvc, nil, slog.Default(),
		); lldpSrc != nil {
			lldpSrc.Start(discCtx)
			activeSources = append(activeSources, "lldp_frame")
		}
		// cdp_frame: passive CDP frame listener (ethertype 0x2000). Only
		// available in WITH_CDP builds (needs CAP_NET_RAW); NewCDPFrameSource
		// returns nil in the default build, so this is a no-op there. Uses the
		// same interface list as LLDP. The host-event path works; neighbor-edge
		// sink deferred until a MAC-keyed device resolver lands.
		if cdpSrc := scannerv2discovery.NewCDPFrameSource(
			cfg.Scanner.Discovery.LLDPInterfaces, discSvc, nil, slog.Default(),
		); cdpSrc != nil {
			cdpSrc.Start(discCtx)
			activeSources = append(activeSources, "cdp_frame")
		}

		discSvc.SetSources(activeSources)
		slog.Info("scannerv2 passive discovery ready",
			"interval", interval.String(),
			"sources", activeSources,
			"trigger_identify", cfg.Scanner.Discovery.TriggerIdentify)
	}

	// Scheduler: cron-driven scan tasks. The ScanFunc delegates to the runner.
	scanScheduler, schedErr := scannerv2scheduler.New(scanQueries, dbConn,
		func(ctx context.Context, taskID int64, targets string, timeout time.Duration, concurrentHosts int, credentialID int64) {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("scan_func_panic", "task_id", taskID, "panic", r)
				}
			}()
			scanRunner.Run(ctx, taskID, targets, timeout, concurrentHosts, cfg.Scanner.PersistRawEvidence, credentialID)
		}, slog.Default())
	if schedErr != nil {
		slog.Error("failed to create scan scheduler", "error", schedErr)
		scanScheduler = nil
	}

	scanTaskService := scannerv2task.New(scanQueries, scanScheduler)
	scannerHandler := handler.NewScannerHandler(v2Engine, scanRunner)
	scannerTaskHandler := handler.NewScannerTaskHandler(scanTaskService)
	scannerResultHandler := handler.NewScannerResultHandler(scanQueries, dbConn)
	r.Route("/api/v1/scanner", func(r chi.Router) {
		// #138 Phase 1b: scanner routes are gated by capability, not a blanket
		// RequireAdmin. admin inherits every capability (unchanged access); the
		// new operator role gains scan access; viewer gains read-only access to
		// results/tasks/runs (same inventory-data class as the RequireAuth device
		// endpoints). Each tier is its own group so the capability matches the
		// action (reads → discovery:read, triggers → scan:trigger, task CRUD +
		// bulk delete → scan:manage, add-devices → device:write).

		// Reads: discovery:read (viewer+). Scan results, task lists, runs.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDiscoveryRead))
			r.Get("/tasks", scannerTaskHandler.ListTasks)
			r.Get("/tasks/{id}", scannerTaskHandler.GetTask)
			r.Get("/tasks/{id}/runs", scannerTaskHandler.GetTaskRuns)
			r.Get("/tasks/{id}/results", scannerTaskHandler.GetTaskResults)
			r.Get("/results", scannerResultHandler.ListResults)
			r.Get("/results/{id}", scannerResultHandler.GetResult)
			r.Get("/runs", scannerResultHandler.ListRuns)
			r.Get("/runs/{id}", scannerResultHandler.GetRun)
			r.Get("/results/export", scannerResultHandler.ExportScanResults)
		})

		// Scan triggers: scan:trigger (operator+). Rate-limited per-IP (these
		// START scans). The rate limiter runs AFTER the capability gate, so a
		// rejected (403) request never consumes a rate token.
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapScanTrigger))
			r.Use(scanLimiter.Middleware)
			r.Post("/scan", scannerHandler.Scan)
			r.Post("/tasks/{id}/trigger", scannerTaskHandler.TriggerTask)
		})

		// Cancel a running scan: scan:trigger (operator+), but NOT rate-limited
		// (it stops a run, doesn't start one).
		r.With(middleware.RequireCapability(domain.CapScanTrigger)).
			Post("/tasks/{id}/cancel", scannerTaskHandler.CancelScanTask)

		// Scan task CRUD + bulk result delete: scan:manage (operator+).
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapScanManage))
			r.Post("/tasks", scannerTaskHandler.CreateTask)
			r.Put("/tasks/{id}", scannerTaskHandler.UpdateTask)
			r.Delete("/tasks/{id}", scannerTaskHandler.DeleteTask)
			r.Delete("/results", scannerResultHandler.BulkDeleteResults)
		})

		// Add devices from a scan: device:write (operator+).
		r.With(middleware.RequireCapability(domain.CapDeviceWrite)).
			Post("/add-devices", scannerHandler.AddDevices)
	})

	// --- SNMP credential management (issue #135 — SNMPv3) ---
	// CRUD for SNMP credentials (v1/v2c community strings + v3 USM auth/priv).
	// Passphrases are AES-GCM-encrypted at rest (security.master_key); the
	// list/get responses never include the secrets (masked projection). Gated by
	// CapCredManage — an admin-only capability (credentials are sensitive even
	// when masked), preserving the prior admin-only semantics.
	credentialHandler := handler.NewCredentialHandler(dbConn, credCipher, credResolver)
	r.Route("/api/v1/snmp-credentials", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapCredManage))
		r.Post("/", credentialHandler.Create)
		r.Get("/", credentialHandler.List)
		r.Get("/{id}", credentialHandler.Get)
		r.Put("/{id}", credentialHandler.Update)
		r.Delete("/{id}", credentialHandler.Delete)
	})

	// SSH credentials for the device config-backup probe (#137). Same gate
	// (CapCredManage, admin-only) + same shared master_key cipher as SNMP.
	sshCredentialHandler := handler.NewSSHCredentialHandler(dbConn, credCipher)
	r.Route("/api/v1/ssh-credentials", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapCredManage))
		r.Post("/", sshCredentialHandler.Create)
		r.Get("/", sshCredentialHandler.List)
		r.Get("/{id}", sshCredentialHandler.Get)
		r.Put("/{id}", sshCredentialHandler.Update)
		r.Delete("/{id}", sshCredentialHandler.Delete)
	})

	// --- Agent token management (distributed phase) ---
	// CRUD for discovery-agent bearer tokens, gated by CapAgentManage
	// (admin-only capability). The ingestion endpoint (/agents/report below)
	// authenticates via RequireAgentToken against this table; this block is the
	// management surface.
	agentAdminHandler := handler.NewAgentAdminHandler(scanQueries)
	r.Route("/api/v1/agents/tokens", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapAgentManage))
		r.Post("/", agentAdminHandler.Create)
		r.Get("/", agentAdminHandler.List)
		r.Post("/{id}/revoke", agentAdminHandler.Revoke)
		r.Delete("/{id}", agentAdminHandler.Delete)
	})

	// --- Agent ingestion (distributed phase) ---
	// The report endpoint is the center-side counterpart to an agent's reporter:
	// remote agents POST their scan results here. Auth is the machine-to-machine
	// RequireAgentToken path (NOT the admin/user JWT above) — the agent's token
	// binds the request to an agent_id + network_id, and every reported device is
	// tagged with that network so multi-LAN data coexists without collision.
	// Routed on the top-level mux (separate from /agents/tokens) so the two auth
	// regimes don't interfere.
	agentReportHandler := handler.NewAgentReportHandler(scanRunner, scanQueries, dbConn)
	agentCommandHandler := handler.NewAgentCommandHandler(scanQueries)
	r.Route("/api/v1/agents", func(r chi.Router) {
		r.Use(middleware.RequireAgentToken)
		r.Post("/report", agentReportHandler.Report)
		// Agent command channel (Phase 5c): the agent polls pending commands
		// (GET /commands), acknowledges (POST /commands/{id}/ack), executes, and
		// reports the result (POST /commands/{id}/complete). Pull model.
		r.Get("/commands", agentCommandHandler.Poll)
		r.Post("/commands/{id}/ack", agentCommandHandler.Ack)
		r.Post("/commands/{id}/complete", agentCommandHandler.Complete)
	})

	// Admin-side command management: enqueue a command for an agent (POST) +
	// view all commands (GET). Separate route group (CapAgentManage, not agent
	// token).
	r.Route("/api/v1/agents/{agentId}/commands", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapAgentManage))
		r.Post("/", agentCommandHandler.Create)
	})
	r.With(middleware.RequireCapability(domain.CapAgentManage)).Get("/api/v1/agents/commands/all", agentCommandHandler.ListAll)

	// --- Change history query (Phase 3) ---
	// GET /api/v1/changes returns the device_added/changed/lost event stream
	// written by the change-detection engine. Auth-gated (any logged-in user);
	// filterable by network_id / change_type / entity_type. This is the
	// queryable view on top of change_log; the in-process Watcher (changeWatcher
	// above) is the foundation for a future /watch SSE push endpoint.
	changeLogHandler := handler.NewChangeLogHandler(scanQueries, dbConn)
	changeWatchHandler := handler.NewChangeWatchHandler(changeWatcher, slog.Default())
	r.Route("/api/v1/changes", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapChangesRead))
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Get("/", changeLogHandler.List)
		r.Get("/watch", changeWatchHandler.Watch)
	})

	// Passive discovery status: runtime counters (events received, dedup hits,
	// identify triggers, devices recorded) + the last few discovery outcomes +
	// which sources are active. Auth-gated (any logged-in user). Returns
	// enabled=false when discovery is off or the service was never started.
	r.Route("/api/v1/discovery", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapDiscoveryRead))
		r.Get("/status", handler.DiscoveryStatusHandler(discSvcForStatus))
	})

	// --- Scanner background services (v2) ---
	// Retention sweeper prunes all high-volume detail tables (heartbeat_results,
	// scan_results, scan_task_runs, audit_logs, notification_log,
	// service_evidence) on a single ticker, each with its own retention window.
	// Defaults & scanner.retention_days back-compat are applied in
	// config.normalizeRetention, so cfg.Retention is fully populated here.
	cleanupSvc := scannerv2cleanup.New(scanQueries, hbStore.Queries(), hbStore.DB(), dbConn, cfg.Retention)
	cleanupSvc.Start(context.Background())

	// Config-backup sweep (#137): fetches running-configs over SSH for devices
	// with a bound SSH credential. Opt-in (scanner.config_backup.enabled) — needs
	// security.master_key + bound creds to do anything useful.
	var configBackupSvc *scannerv2configbackup.Service
	if cfg.Scanner.ConfigBackup.Enabled {
		sshResolver := sshcred.New(dbConn, credCipher)
		configBackupSvc = scannerv2configbackup.New(
			dbConn, scanQueries, sshResolver, changeRecorder, scannerv2configbackup.FetchConfig,
			time.Duration(cfg.Scanner.ConfigBackup.Interval)*time.Second,
			time.Duration(cfg.Scanner.ConfigBackup.Timeout)*time.Second,
			slog.Default(),
		)
		configBackupSvc.Start(context.Background())
		slog.Info("config-backup sweep started",
			"interval_s", cfg.Scanner.ConfigBackup.Interval, "timeout_s", cfg.Scanner.ConfigBackup.Timeout)
	}

	if scanScheduler != nil {
		scanScheduler.Start(context.Background())
	}
	// Audit log routes — CapAuditRead. The capability matrix (#217) grants
	// audit:read to every read-capable role (admin/operator/viewer/+legacy user):
	// in a CMDB/monitoring tool a read-only stakeholder seeing the "who changed
	// what when" trail is reasonable transparency (cf. NetBox change-logs). This
	// widens the prior admin-only read to viewer+; if a future deployment needs
	// stricter audit visibility, gate on CapAuditManage (admin-only) instead.
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapAuditRead))
		r.Get("/api/v1/audit-logs", auditHandler.List)
		r.Get("/api/v1/audit-logs/facets", auditHandler.Facets)
		r.Get("/api/v1/audit-logs/export", exportHandler.ExportAuditLogs)
	})

	// Device system routes
	deviceSystemRepo := service.NewDeviceSystemRepository(dbConn)
	deviceSystemSvc := service.NewDeviceSystemService(deviceSystemRepo)
	deviceSystemHandler := handler.NewDeviceSystemHandler(deviceSystemSvc)
	r.Route("/api/v1/devices/{id}/systems", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceRead))
			r.Get("/", deviceSystemHandler.ListByDevice)
			r.Get("/{systemId}", deviceSystemHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDeviceWrite))
			r.Post("/", deviceSystemHandler.Create)
			r.Put("/{systemId}", deviceSystemHandler.Update)
			r.Delete("/{systemId}", deviceSystemHandler.Delete)
		})
	})

	// Device L2 neighbors (Bridge-MIB / LLDP / CDP / ARP) — read-only. Feeds
	// the detail-page Neighbors panel.
	r.Route("/api/v1/devices/{id}/neighbors", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapDeviceRead))
		r.Get("/", neighborHandler.ListByDevice)
	})

	// Device TLS certificates (https/ldaps/imaps/etc) — read-only. Feeds the
	// detail-page TLS Certificates sub-panel and the per-port certificate Modal
	// (full chain + PEM).
	r.Route("/api/v1/devices/{id}/certificates", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapDeviceRead))
		r.Get("/", tlsCertHandler.ListByDevice)
	})

	// Device running-config history (#137, Oxidized/RANCID-style) — read-only.
	// The list omits config_text; the detail + diff views load it on demand.
	// Registered before /{configId} so the static /diff segment wins over the
	// param (chi prefers literal over wildcard).
	r.Route("/api/v1/devices/{id}/configs", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapConfigRead))
		r.Get("/", deviceConfigHandler.List)
		r.Get("/diff", deviceConfigHandler.Diff)
		r.Get("/{configId}", deviceConfigHandler.Get)
	})

	// Network-level topology graph — all devices (nodes) + all neighbor edges.
	// Read-only. Feeds the /topology page.
	r.Route("/api/v1/topology", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapTopologyRead))
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Get("/", topologyHandler.Graph)
	})

	// Document routes
	uploadPath := cfg.Storage.UploadPath
	if uploadPath == "" {
		uploadPath = "./data/uploads"
	}
	maxFileSize := cfg.Storage.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = 10485760
	}
	uploadSvc := service.NewUploadService(uploadPath, maxFileSize)
	docSvc := service.NewDocumentService(dbConn, uploadSvc)
	docHandler := handler.NewDocumentHandler(docSvc, uploadPath, auditRepo)
	r.Route("/api/v1/documents", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDocumentRead))
			r.Get("/", docHandler.List)
			r.Get("/{id}", docHandler.Get)
			r.Get("/{id}/download", docHandler.Download)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDocumentWrite))
			r.Post("/", docHandler.CreateURL)
			r.Post("/upload", docHandler.UploadFile)
			r.Put("/{id}", docHandler.Update)
			r.Delete("/{id}", docHandler.Delete)
		})
	})

	// Heartbeat routes
	go heartbeatSvc.Start(context.Background())
	heartbeatHandler := handler.NewHeartbeatHandler(heartbeatSvc)

	// Device heartbeat configs
	r.Route("/api/v1/devices/{id}/heartbeat-configs", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapHeartbeatRead))
			r.Get("/", heartbeatHandler.ListConfigs)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapHeartbeatManage))
			r.Post("/", heartbeatHandler.CreateConfig)
		})
	})

	// Heartbeat config CRUD
	r.Route("/api/v1/heartbeat-configs", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapHeartbeatManage))
		r.Put("/{id}", heartbeatHandler.UpdateConfig)
		r.Delete("/{id}", heartbeatHandler.DeleteConfig)
	})

	// Heartbeat results
	r.Route("/api/v1/devices/{id}/heartbeat-results", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapHeartbeatRead))
		r.Get("/export", exportHandler.ExportHeartbeatResults)
		r.Get("/", heartbeatHandler.ListResults)
	})

	// Heartbeat history and stats
	r.Group(func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Use(middleware.RequireCapability(domain.CapHeartbeatRead))
		r.Get("/api/v1/devices/{id}/heartbeat-history", heartbeatHandler.ListHistory)
		r.Get("/api/v1/devices/{id}/heartbeat-stats", heartbeatHandler.GetStats)
	})
	// Dashboard routes
	dashSvc := service.NewDashboardService(dbConn, cfg)
	dashHandler := handler.NewDashboardHandler(dashSvc)
	r.Route("/api/v1/dashboard", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDashboardRead))
			r.Use(middleware.NetworkScope(scopeResolver))
			r.Get("/configs", dashHandler.ListConfigs)
			r.Get("/overview", dashHandler.Overview)
			r.Get("/query", dashHandler.Query)
			r.Get("/query_range", dashHandler.QueryRange)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDashboardManage))
			r.Post("/configs", dashHandler.CreateConfig)
			r.Put("/configs/{id}", dashHandler.UpdateConfig)
			r.Delete("/configs/{id}", dashHandler.DeleteConfig)
		})
	})

	// Device-Document linking routes
	linkHandler := handler.NewLinkHandler(dbConn, auditRepo)
	r.Route("/api/v1/devices/{id}/documents", func(r chi.Router) {
		r.Use(middleware.NetworkScope(scopeResolver))
		r.Use(middleware.ValidateDeviceScope(dbConn))
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDocumentRead))
			r.Get("/", linkHandler.GetDeviceDocuments)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireCapability(domain.CapDocumentWrite))
			r.Post("/", linkHandler.LinkDocument)
			r.Delete("/{docId}", linkHandler.UnlinkDocument)
		})
	})
	r.Route("/api/v1/documents/{id}/devices", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapDocumentRead))
		r.Get("/", linkHandler.GetDocumentDevices)
	})

	// Notification service, dispatcher, and handler
	notificationSvc := service.NewNotificationService(db.New(dbConn))
	notificationDispatcher := notification.NewDispatcher(db.New(dbConn), nil)
	notificationDispatcher.Start(context.Background())
	notificationHandler := handler.NewNotificationHandler(notificationSvc, notificationDispatcher, auditRepo)

	// Notification rule engine (#139): subscribes to changedetect.Watcher and
	// dispatches matching rules via notificationDispatcher. Shares the same
	// changeWatcher singleton as the /changes/watch SSE handler (independent
	// subscriber channels). Started here; stopped in the shutdown cleanup below.
	ruleEngine := notification.NewRuleEngine(scanQueries, changeWatcher, notificationDispatcher, slog.Default())
	ruleEngine.Start(context.Background())

	// Notification channel routes — CapNotificationManage (admin-only
	// capability). Channels carry webhook URLs / tokens, so even the masked
	// read stays admin-only.
	r.Route("/api/v1/notification/channels", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapNotificationManage))
		r.Post("/", notificationHandler.CreateChannel)
		r.Get("/", notificationHandler.ListChannels)
		r.Get("/{id}", notificationHandler.GetChannel)
		r.Put("/{id}", notificationHandler.UpdateChannel)
		r.Patch("/{id}", notificationHandler.SetChannelEnabled)
		r.Delete("/{id}", notificationHandler.DeleteChannel)
		r.Post("/{id}/test", notificationHandler.TestChannel)
	})

	// Notification rule routes — CapNotificationManage (rules are config, like
	// channels).
	r.Route("/api/v1/notification/rules", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapNotificationManage))
		r.Post("/", notificationHandler.CreateRule)
		r.Get("/", notificationHandler.ListRules)
		r.Get("/{id}", notificationHandler.GetRule)
		r.Put("/{id}", notificationHandler.UpdateRule)
		r.Patch("/{id}", notificationHandler.SetRuleEnabled)
		r.Delete("/{id}", notificationHandler.DeleteRule)
	})

	// Notification log routes — every authenticated user sees the header bell
	// and has their own per-user read state, so logs + mark-as-read are
	// RequireAuth (NOT RequireAdmin). Channel CRUD above stays admin-only.
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/api/v1/notification/logs", notificationHandler.ListNotificationLogs)
		r.Post("/api/v1/notification/logs/read", notificationHandler.MarkAllNotificationLogsRead)
	})

	// Prometheus metrics + HTTP service discovery are PUBLIC: Prometheus
	// scrapes these endpoints without credentials, and they leak no secrets
	// (metrics are aggregate counters; SD exposes only device IPs/labels
	// that the scanner already published). Keep them out of RequireAuth/Admin.
	r.Handle("/metrics", handler.MetricsHandler())
	sdHandler := handler.NewSDHandler(dbConn, deviceSystemRepo)
	r.Get("/sd", sdHandler.ServeHTTP)

	// Seed initial device metrics
	go handler.UpdateDeviceMetrics(context.Background(), dbConn)
	// SPA handler — serves embedded frontend
	spaHandler := handler.NewSPAHandler()
	r.Mount("/", spaHandler)

	return r, heartbeatSvc, func() {
		if scanScheduler != nil {
			scanScheduler.Stop()
		}
		// Stop the lease sweeper BEFORE the DB close — its sweepOnce runs
		// UPDATE devices + recordDeviceLost (change_log INSERT) and must not
		// race db.Close(). Cancel unblocks an in-flight sweep's ctx-aware DB
		// calls, then Stop() waits for the goroutine to fully exit. (#163)
		leaseSweepCancel()
		leaseSweeper.Stop()
		// Stop the reconciliation job BEFORE the DB close — its scan reads
		// devices/networks and must not race db.Close().
		reconcileCancel()
		reconciler.Stop()
		// Stop the passive discovery sources + coordinator BEFORE the DB close —
		// the coordinator's known-host pre-check and the sources' walks hold
		// open DB/SNMP handles that must not race db.Close().
		if discCancel != nil {
			discCancel()
		}
		discSvc.Stop()
		cleanupSvc.Stop()
		if configBackupSvc != nil {
			configBackupSvc.Stop()
		}
		// Stop the rule engine BEFORE the dispatcher — it holds a Watcher
		// subscriber and calls dispatcher.Dispatch; stopping it first prevents
		// in-flight dispatch attempts against a stopped dispatcher.
		ruleEngine.Stop()
		// Stop the notification dispatcher's worker goroutines too. Without
		// this, the 3 workers (and their *db.Queries handle) outlive graceful
		// shutdown and race against db.Close() in main.go.
		notificationDispatcher.Stop()
		// Stop the rate-limiter cleanup goroutines (process-lifetime, but
		// close cleanly instead of leaking). (#163)
		loginLimiter.Stop()
		globalLimiter.Stop()
		scanLimiter.Stop()
	}
}

// parseDurationOrDefault parses a Go duration string, returning def on empty or
// parse error. Used for optional background-loop timing config keys.
func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

// routerResidentSourcesOn reports whether any of the discovery sources that
// only yield data when the host IS the gateway are enabled. When true AND
// router_arp is also on, router_arp is redundant (the gateway's own
// arp_cache/dhcp_leases/conntrack cover the same hosts authoritatively, without
// an extra SNMP walk) — used to emit the redundancy warning at startup.
func routerResidentSourcesOn(d config.DiscoveryConfig) bool {
	return d.ARPCache.Enabled || d.DHCPLeases.Enabled || d.Conntrack.Enabled
}

// routerCommunity resolves the SNMP community for cross-subnet ARP walks:
// prefer the dedicated router_arp.community, fall back to the global snmp_community.
func routerCommunity(cfg config.ScannerConfig) string {
	if cfg.RouterARP.Community != "" {
		return cfg.RouterARP.Community
	}
	if cfg.SNMPCommunity != "" {
		return cfg.SNMPCommunity
	}
	return "public"
}

// routerTimeout resolves the per-router ARP-walk timeout in seconds (default 4).
func routerTimeout(cfg config.ScannerConfig) int {
	if cfg.RouterARP.Timeout > 0 {
		return cfg.RouterARP.Timeout
	}
	return 4
}

// buildCredentialCipher constructs the AES-GCM cipher + credential resolver
// from security.master_key. Returns (nil, nil) when the key is unset or
// invalid (so the engine + handler gracefully degrade to v1/v2c). Logs the
// reason on failure so the operator can see why v3 is unavailable.
func buildCredentialCipher(dbConn *sql.DB, cfg *config.Config) (*crypto.Cipher, *credresolver.Resolver) {
	if cfg.Security.MasterKey == "" {
		return nil, nil
	}
	if len(cfg.Security.MasterKey) != crypto.MasterKeyLen {
		slog.Error("security.master_key wrong length (must be exactly 32 bytes); SNMPv3 credential storage disabled",
			"length", len(cfg.Security.MasterKey))
		return nil, nil
	}
	c, err := crypto.NewCipher([]byte(cfg.Security.MasterKey))
	if err != nil {
		slog.Error("security.master_key invalid; SNMPv3 credential storage disabled", "error", err)
		return nil, nil
	}
	slog.Info("SNMPv3 credential resolver enabled",
		"master_key_fingerprint", c.KeyFingerprint([]byte(cfg.Security.MasterKey)))
	return c, credresolver.New(dbConn, c)
}

// rdnsTimeout returns the configured rDNS lookup deadline (seconds), default 2.
func rdnsTimeout(cfg config.ScannerConfig) int {
	if cfg.RDNS.Timeout > 0 {
		return cfg.RDNS.Timeout
	}
	return 2
}

// heartbeatDBPathFor derives the heartbeat.db path from the main DB path:
// same directory, filename "heartbeat.db". This keeps the time-series store
// alongside the main database (e.g. ./data/heartbeat.db next to ./data/mibee.db).
func heartbeatDBPathFor(cfg *config.Config) string {
	mainPath := cfg.Database.SQLite.Path
	if mainPath == "" {
		mainPath = "./data/mibee.db"
	}
	return filepath.Join(filepath.Dir(mainPath), "heartbeat.db")
}

// resolveNetworkID upserts the networks row for this instance's configured
// network (config `network.name`/cidr/site) and returns its id. The returned id
// is stamped onto every device this instance discovers (devices.network_id) so
// multiple instances on different LANs can coexist without IP-key collisions.
//
// Empty/missing name resolves to "default" so single-instance deployments still
// tag their devices (network_id non-NULL), which keeps the (ip, network_id)
// composite-unique index deterministic. Returns 0 only on a hard DB error
// (logged; devices then fall back to NULL network_id and the legacy IP path).
func resolveNetworkID(dbConn *sql.DB, cfg *config.Config) int64 {
	name := cfg.Network.Name
	if name == "" {
		name = "default"
	}
	// Upsert by name: update cidr/site if the row exists, else insert.
	res, err := dbConn.Exec(`
		INSERT INTO networks (name, cidr, site)
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO NOTHING`,
		name, cfg.Network.CIDR, cfg.Network.Site)
	if err != nil {
		slog.Error("resolve network id: upsert networks failed; devices will have NULL network_id",
			"name", name, "error", err)
		return 0
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Row already existed — refresh its cidr/site in case the config changed.
		_, _ = dbConn.Exec(`UPDATE networks SET cidr = ?, site = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?`,
			cfg.Network.CIDR, cfg.Network.Site, name)
	}
	var id int64
	if err := dbConn.QueryRow(`SELECT id FROM networks WHERE name = ?`, name).Scan(&id); err != nil {
		slog.Error("resolve network id: lookup failed; devices will have NULL network_id",
			"name", name, "error", err)
		return 0
	}

	// Backfill: tag every pre-existing device that has no network_id with this
	// instance's network. Without this, a rescan of a legacy (network_id NULL)
	// device would create a DUPLICATE row keyed on (ip, <resolved network_id>)
	// instead of updating the original — the (ip, NULL) and (ip, N) composite
	// keys are distinct in the unique index. This is only safe for the
	// single-instance default; a true multi-agent deployment would reconcile via
	// the center, not backfill blindly.
	if res, err := dbConn.Exec(`UPDATE devices SET network_id = ? WHERE network_id IS NULL`, id); err != nil {
		slog.Warn("resolve network id: device backfill failed; legacy devices keep NULL network_id",
			"network_id", id, "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("network identity resolved; tagged pre-existing devices", "id", id, "name", name, "cidr", cfg.Network.CIDR, "devices_tagged", n)
		return id
	}

	slog.Info("network identity resolved", "id", id, "name", name, "cidr", cfg.Network.CIDR)
	return id
}
