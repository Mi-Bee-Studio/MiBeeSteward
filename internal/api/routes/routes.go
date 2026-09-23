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
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/authz/scoperesolver"
	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/dbopen"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/demoseed"
	"mibee-steward/internal/service/notification"
	probetarget "mibee-steward/internal/service/probetarget"
	scannerv2 "mibee-steward/internal/service/scannerv2"
	scannerv2cleanup "mibee-steward/internal/service/scannerv2/cleanup"
	scannerv2configbackup "mibee-steward/internal/service/scannerv2/configbackup"
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
	// Initialize token blacklist for JWT revocation. Entries expire lazily
	// on read, no cleanup goroutine to leak per NewRouter call.
	tokenBlacklist := service.NewTokenBlacklist()
	middleware.SetTokenBlacklist(tokenBlacklist)

	// Parse token expiry, default to 24h
	expiry := 24 * time.Hour
	if cfg.Auth.TokenExpiry != "" {
		if d, err := time.ParseDuration(cfg.Auth.TokenExpiry); err == nil {
			expiry = d
		}
	}

	// Settings-center overlay (system_settings): runtime-editable settings
	// resolved overlay > YAML > defaults by the services that consume them.
	// A load failure degrades to config-only (writes 503) rather than taking
	// the whole center down.
	settingsSvc, err := service.NewSettingsService(dbConn)
	if err != nil {
		slog.Warn("settings overlay unavailable; continuing with config-only settings", "error", err)
		settingsSvc = nil
	}

	// User service and handler
	userSvc := service.NewUserService(dbConn, cfg.Auth.JWTSecret, expiry, cfg.Auth.PasswordPolicy)

	// Session-epoch source (#357): the Authenticator rejects tokens whose `tv`
	// claim lags the user's current token_version (bumped on password change).
	middleware.SetTokenVersionSource(userSvc.TokenVersion)
	userSvc.SetLockoutPolicy(cfg.Auth.Lockout)
	if settingsSvc != nil {
		userSvc.SetSettingsSource(settingsSvc)
	}
	// Audit logging
	// SQLITE_BUSY governance (#267): each hot write path gets its own
	// dbopen.BusyRetry wrapper, bounded retry with backoff plus the
	// mibee_sqlite_busy_total{path} counter. Paths that share dbConn below
	// construct their queries from these wrapped handles.
	scannerDB := dbopen.WrapBusyRetry(dbConn, "scanner")
	auditDB := dbopen.WrapBusyRetry(dbConn, "audit")
	probeDB := dbopen.WrapBusyRetry(dbConn, "probe")
	notifyDB := dbopen.WrapBusyRetry(dbConn, "notification")

	auditRepo := service.NewAuditRepository(auditDB)

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
	// use the TCP peer as the client, safe for direct exposure). Deploy behind
	// nginx and set trusted_proxies to the proxy's source range (#133).
	r.Use(middleware.RealIP(middleware.ParseCIDRs(cfg.Server.TrustedProxies)))
	r.Use(middleware.Logging)
	r.Use(middleware.Metrics)
	r.Use(chimw.Recoverer)
	r.Use(middleware.CORS(cfg.CORS.AllowedOrigins))
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.CSRF)
	r.Use(globalLimiter.Middleware)

	// API routes (public: health, login, metrics, sd, demo status)
	r.Get("/api/v1/health", handler.HealthHandler(dbConn))

	// Demo mode (#285): on an EMPTY database the first boot seeds the
	// fictional inventory (RFC 5737 TEST-NET ranges only, never a real
	// network) and an activity ticker keeps the dashboard moving. /demo/status
	// is public so the SPA can show the banner pre-login; wiping is admin.
	// Local (not package-global) so a second NewRouter can't overwrite and
	// orphan the first instance's activity goroutine.
	var demoActivity *demoseed.Activity
	if cfg.Server.DemoMode {
		if demoseed.IsDemoEmpty(dbConn) {
			if err := demoseed.Seed(context.Background(), dbConn, slog.Default()); err != nil {
				slog.Warn("demo seed failed", "error", err)
			}
		} else {
			slog.Info("demo mode active; database not empty, skipping seed")
		}
		demoActivity = demoseed.StartActivity(dbConn, slog.Default())
		r.Get("/api/v1/demo/status", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"demo": true}`))
		})
		r.With(middleware.RequireCapability(domain.CapDeviceWrite)).Post("/api/v1/demo/wipe", func(w http.ResponseWriter, req *http.Request) {
			if err := demoseed.Wipe(req.Context(), dbConn); err != nil {
				handler.Error(w, http.StatusInternalServerError, "failed to wipe demo data")
				return
			}
			handler.Success(w, map[string]string{"message": "demo data wiped; scan a real subnet to populate the inventory"})
		})
		slog.Info("demo mode enabled — fictional inventory seeded, activity ticker running")
	}

	registerAuthRoutes(r, loginLimiter, userHandler, totpHandler)

	// Object-level network scope resolver (#138 Phase 2). Resolves a user's
	// granted network set (closed mode) or Global (admin / open mode). Consumed
	// by NetworkScope (injects scope into context), the device query paths, and
	// the network-grant management handler (Phase 3, for cache invalidation).
	scopeResolver := scoperesolver.New(dbConn, domain.ScopeMode(cfg.RBAC.ScopeDefault))
	// Network-grant management handler (#138 Phase 3): admin assigns/removes a
	// user's network scope. CapUserManage = admin-only. The handler invalidates
	// the scope resolver cache per affected user so changes apply immediately.
	networkGrantHandler := handler.NewNetworkGrantHandler(dbConn, scopeResolver)

	registerUserRoutes(r, userHandler, batchHandler, networkGrantHandler)

	// Settings center: runtime-editable configuration overlay (auth password
	// policy + login lockout today; engine knobs subscribe later). Writes are
	// admin-only (CapUserManage) and land in system_settings, effective on
	// the next validation/login, no restart. /system is read-only instance
	// info for every signed-in role.
	settingsHandler := handler.NewSettingsHandler(settingsSvc, userSvc, cfg, auditRepo)
	registerSettingsRoutes(r, settingsHandler)
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

	// Export handler, bound to the main DB for devices/audit, and to the
	// dedicated heartbeat store for heartbeat_results (which lives in
	// heartbeat.db after the time-series split; the main DB's copy is stale).
	exportHandler := handler.NewExportHandler(service.NewExportService(db.New(dbConn), hbStore.Queries(), dbConn))

	// Device routes
	deviceRepo := service.NewDeviceRepository(dbConn)
	deviceSvc := service.NewDeviceService(deviceRepo, heartbeatSvc)
	deviceHandler := handler.NewDeviceHandler(deviceSvc)
	registerDeviceRoutes(r, exportHandler, deviceHandler, batchHandler, scopeResolver, dbConn)
	// Scanner routes (v2 engine)
	scanQueries := db.New(dbConn)
	// Wire the DB querier for agent-token verification (RequireAgentToken). Done
	// here so the ingestion routes (registered below) can authenticate agents.
	middleware.SetAgentQueries(scanQueries)

	// Network registry, feeds the device-list + change-history network filters
	// and the Networks admin page. Read (List) is any logged-in user; create/
	// update/delete require CapNetworkManage (admin-only capability).
	networkSvc := service.NewNetworkService(scanQueries, dbConn)
	networkHandler := handler.NewNetworkHandler(scanQueries, networkSvc)
	registerNetworkRoutes(r, networkHandler)

	// L2 topology, neighbors per device (detail page) + the whole-network
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

	// Passive-discovery seed evidence (#377): the discovery service (created
	// below, the engine is also its identify target, hence the late binding)
	// caches overheard hostnames/mDNS/SSDP announcements; every scan pulls
	// them as seed evidence ahead of classification, so the fingerprint rules
	// see the passive channel even when active queries go unanswered.
	var discSvcRef *scannerv2discovery.Service
	seedFromPassive := func(ip string) []scannerv2.Evidence {
		if discSvcRef == nil {
			return nil
		}
		return discSvcRef.EvidenceFor(ip)
	}

	v2Engine, engineErr := scannerv2engine.NewEngine(dbConn, scannerv2engine.Config{
		PortSpec:             scannerPortSpec,
		MaxConcurrentHosts:   cfg.Scanner.MaxConcurrentHosts,
		AllowReservedTargets: cfg.Scanner.AllowReservedTargets,
		MaxConcurrentScans:   cfg.Scanner.MaxConcurrentScans,
		PerHostTimeout:       time.Duration(cfg.Scanner.DefaultTimeout) * time.Second,
		PerProbeTimeout:      time.Duration(cfg.Scanner.PerProbeTimeout) * time.Second,
		PersistRawEvidence:   cfg.Scanner.PersistRawEvidence,
		SeedEvidence:         seedFromPassive,
		OUIPath:              cfg.Scanner.OUIPath,
		FingerprintPath:      cfg.Scanner.FingerprintPath,
		SNMPCommunity:        cfg.Scanner.SNMPCommunity,
		CredResolver:         credResolver,
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
	scanRunner := scannerv2runner.New(v2Engine, scanQueries, scannerDB, heartbeatSvc, networkID, slog.Default())
	scanRunner.SetRepo(v2Engine.Repository)                // device-identity upsert (ResolveDeviceIdentity / ApplyDeviceIdentity)
	scanRunner.SetLostThreshold(cfg.Scanner.LostThreshold) // scanner.lost_threshold (default 2; <=0 keeps default)

	// Change detection (Phase 3): the center records device_added/changed/lost
	// events to change_log + pushes in-process Watcher subscribers. The agent
	// does NOT set this (change detection is a center concern; agents only
	// forward raw HostReports). The watcher is the foundation for a future
	// /watch SSE endpoint (Step 4 exposes a query API on top of change_log).
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
	// (networks.agent_id non-empty), the center's own network keeps using
	// the local-scan DetectLost path + heartbeat. Stopped in the cleanup
	// closure below before db.Close().
	leaseTTL := parseDurationOrDefault(cfg.Scanner.AgentLeaseTTL, 5*time.Minute)
	leaseSweepInterval := parseDurationOrDefault(cfg.Scanner.LeaseSweepInterval, 60*time.Second)
	leaseSweepCtx, leaseSweepCancel := context.WithCancel(context.Background())
	leaseSweeper := scannerv2runner.NewLeaseSweeper(scanRunner, leaseSweepInterval, leaseTTL, slog.Default())
	leaseSweeper.Start(leaseSweepCtx)

	// Network-attribution reconciliation (issue #19 Layer 3): a slow background
	// audit that detects devices whose IP has drifted outside their stamped
	// network's CIDR. This is the bottom-line defense, it catches drift the
	// Layer 1 (dispatch) + Layer 2 (ingestion) boundary checks miss (e.g. a
	// network without a cidr, or a future code path that bypasses them).
	// Detect-and-report only; correction stays a human decision (Layer 4).
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
		scannerv2discovery.SinkAdapter{
			Runner:   scanRunner,
			Networks: scannerv2discovery.NewNetworkResolver(dbConn), // #386: attribute sightings to the network whose CIDR contains them
		},
		scannerv2discovery.IdentifierAdapter(v2Engine),
		dbConn, networkID, prometheus.DefaultRegisterer, slog.Default(),
	)
	// Late-bind the seed-evidence closure (#377): the engine was constructed
	// before the discovery service exists (the service needs the engine as its
	// identify target), so the closure captured a placeholder pointer.
	discSvcRef = discSvc
	var discCancel context.CancelFunc
	// discSvcForStatus carries the discovery service to the status endpoint.
	// nil when the service was never started (discovery disabled), the handler
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
		// - it walks a router's SNMP ARP table from across the subnet to recover
		// cross-subnet MACs the center can't see at L2. When the center runs ON
		// the gateway (form C, deploy/openwrt/) the router's OWN sources cover the
		// same hosts authoritatively (and more, dhcp_leases, conntrack, hostapd),
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
			arpCacheSrc := scannerv2discovery.NewARPCacheSource(cfg.Network.CIDR, interval, discSvc, slog.Default())
			arpCacheSrc.Start(discCtx)
			activeSources = append(activeSources, "arp_cache")
		}
		// multicast: passive mDNS/SSDP listener (zero outbound traffic).
		if cfg.Scanner.Discovery.Multicast.Enabled {
			mcastSrc := scannerv2discovery.NewMulticastSource(discSvc, slog.Default())
			mcastSrc.Start(discCtx)
			activeSources = append(activeSources, "multicast")
		}
		// dhcp_leases: Tier-1 router signal, the DHCP authority's hostname↔MAC↔IP
		// map. No-op on a host that isn't the LAN's DHCP server (file absent).
		if cfg.Scanner.Discovery.DHCPLeases.Enabled {
			dhcpSrc := scannerv2discovery.NewDHCPLeasesSource(interval, "", discSvc, slog.Default())
			dhcpSrc.Start(discCtx)
			activeSources = append(activeSources, "dhcp_leases")
		}
		// conntrack: Tier-1 router signal, the NAT choke point's "who is talking
		// RIGHT NOW" view. Filters to the center's own LAN CIDR.
		if cfg.Scanner.Discovery.Conntrack.Enabled {
			conntrackSrc := scannerv2discovery.NewConntrackSource(cfg.Network.CIDR, interval, discSvc, slog.Default())
			conntrackSrc.Start(discCtx)
			activeSources = append(activeSources, "conntrack")
		}
		// hostapd: Tier-1 router/AP signal, WiFi STA associations (signal dBm,
		// connect time, SSID). hostapd ctrl socket first, iw station dump fallback.
		if cfg.Scanner.Discovery.Hostapd.Enabled {
			hostapdSrc := scannerv2discovery.NewHostapdSource(cfg.Scanner.Discovery.Hostapd.Interfaces, interval, discSvc, slog.Default())
			hostapdSrc.Start(discCtx)
			activeSources = append(activeSources, "hostapd")
		}
		// dns_log: Tier-1 router signal, tails the dnsmasq query log for passive
		// DNS fingerprinting (devices that block inbound probes still do DNS).
		if cfg.Scanner.Discovery.DNSLog.Enabled {
			dnsLogSrc := scannerv2discovery.NewDNSLogSource(interval, cfg.Scanner.Discovery.DNSLog.Path, discSvc, slog.Default())
			dnsLogSrc.Start(discCtx)
			activeSources = append(activeSources, "dns_log")
		}
		// arp_scan: active ARP who-has sweep of the whole network CIDR. The only
		// source that covers the entire broadcast domain with NO router access
		// (every host must answer ARP, even firewalled ones). Needs the
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

	// Agent command service: constructed BEFORE the scheduler so the ScanFunc
	// binding below can close over it (agent-network tasks dispatch through it
	// instead of running a local scan).
	agentCmdSvc := service.NewAgentCommandService(scanQueries, cfg.AgentFleet.RemoteOpsEnabled, cfg.Scanner.AllowReservedTargets)

	// Scheduler: cron-driven scan tasks. The ScanFunc binding is the
	// local-vs-agent dispatcher: a task whose resolved network is
	// agent-managed (networks.agent_id set) has no local scanner path, the
	// agent IS the scanner there, so the tick enqueues a scan command for
	// that agent; everything else runs the local pipeline via the runner.
	scanScheduler, schedErr := scannerv2scheduler.New(scanQueries, dbConn,
		func(ctx context.Context, taskID int64, targets string, timeout time.Duration, concurrentHosts int, credentialID int64, networkID *int64) {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("scan_func_panic", "task_id", taskID, "panic", r)
				}
			}()
			if agentID := agentForNetwork(dbConn, networkID); agentID != "" {
				dispatchAgentScan(ctx, dbConn, scanQueries, agentCmdSvc, taskID, targets, timeout, agentID, credentialID)
				return
			}
			scanRunner.Run(ctx, taskID, targets, timeout, concurrentHosts, cfg.Scanner.PersistRawEvidence, credentialID)
		}, slog.Default())
	if schedErr != nil {
		slog.Error("failed to create scan scheduler", "error", schedErr)
		scanScheduler = nil
	}

	scanTaskService := scannerv2task.New(scanQueries, dbConn, scanScheduler, cfg.Scanner.AllowReservedTargets)
	scannerHandler := handler.NewScannerHandler(v2Engine, scanRunner)
	scannerTaskHandler := handler.NewScannerTaskHandler(scanTaskService)
	scannerResultHandler := handler.NewScannerResultHandler(scanQueries, dbConn, service.NewScannerResultService(scanQueries))
	registerScannerRoutes(r, scopeResolver, scanLimiter, scannerHandler, scannerTaskHandler, scannerResultHandler)

	// --- Synthetic probing (拨测): user-configured external targets ---
	// blackbox_exporter-style modules (http/tls/tcp/icmp) against explicit
	// endpoints; the tls leg reuses the scanner's CollectCertChain. Reads →
	// probe:read (viewer+); CRUD + trigger → probe:manage (operator+). NOT
	// network-scoped: #138's object-level scope guards the internal inventory,
	// while probing aims at arbitrary external endpoints by design.
	probeEngine := probetarget.NewEngine(db.New(probeDB), slog.Default(), prometheus.DefaultRegisterer)
	probeTargetSvc := probetarget.New(db.New(probeDB), probeEngine)
	// Vantage probe dispatcher (#277): ships agent plans over the command
	// channel whenever a plan content changes (fingerprint-gated, steady
	// state is zero traffic). Same 10s cadence as the engine tick.
	probeDispatcher := probetarget.NewAgentDispatcher(db.New(probeDB), agentCmdSvc, slog.Default())
	// Stop channel for the dispatch ticker below, without it the goroutine
	// ran forever (one leak per NewRouter call; tests call NewRouter a lot).
	probeDispatchStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-probeDispatchStop:
				return
			case <-ticker.C:
				probeDispatcher.DispatchTick(context.Background())
			}
		}
	}()
	agentProbeReportHandler := handler.NewAgentProbeReportHandler(probeTargetSvc)
	probeTargetHandler := handler.NewProbeTargetHandler(probeTargetSvc, scanQueries)
	registerProbeTargetRoutes(r, probeTargetHandler)

	// --- SNMP credential management (issue #135, SNMPv3) ---
	// CRUD for SNMP credentials (v1/v2c community strings + v3 USM auth/priv).
	// Passphrases are AES-GCM-encrypted at rest (security.master_key); the
	// list/get responses never include the secrets (masked projection). Gated by
	// CapCredManage, an admin-only capability (credentials are sensitive even
	// when masked), preserving the prior admin-only semantics.
	credentialHandler := handler.NewCredentialHandler(dbConn, credCipher, credResolver)
	registerSNMPCredentialRoutes(r, credentialHandler)

	// SSH credentials for the device config-backup probe (#137). Same gate
	// (CapCredManage, admin-only) + same shared master_key cipher as SNMP.
	sshCredentialHandler := handler.NewSSHCredentialHandler(dbConn, credCipher)
	registerSSHCredentialRoutes(r, sshCredentialHandler)

	// --- Agent token management (distributed phase) ---
	// CRUD for discovery-agent bearer tokens, gated by CapAgentManage
	// (admin-only capability). The ingestion endpoint (/agents/report below)
	// authenticates via RequireAgentToken against this table; this block is the
	// management surface.
	agentAdminHandler := handler.NewAgentAdminHandler(scanQueries, service.NewAgentTokenService(scanQueries))
	registerAgentTokenRoutes(r, agentAdminHandler)

	// --- Agent ingestion (distributed phase) ---
	// The report endpoint is the center-side counterpart to an agent's reporter:
	// remote agents POST their scan results here. Auth is the machine-to-machine
	// RequireAgentToken path (NOT the admin/user JWT above), the agent's token
	// binds the request to an agent_id + network_id, and every reported device is
	// tagged with that network so multi-LAN data coexists without collision.
	// Routed on the top-level mux (separate from /agents/tokens) so the two auth
	// regimes don't interfere. agentCmdSvc is constructed above (before the
	// scheduler) so the ScanFunc dispatcher can share the same instance.
	agentReportHandler := handler.NewAgentReportHandler(scanRunner, scanQueries, dbConn, agentCmdSvc)
	agentCommandHandler := handler.NewAgentCommandHandler(scanQueries, agentCmdSvc, auditRepo)
	registerAgentRoutes(r, agentReportHandler, agentProbeReportHandler, agentCommandHandler)

	registerAgentCommandAdminRoutes(r, agentCommandHandler)

	// --- Change history query (Phase 3) ---
	// GET /api/v1/changes returns the device_added/changed/lost event stream
	// written by the change-detection engine. Auth-gated (any logged-in user);
	// filterable by network_id / change_type / entity_type. This is the
	// queryable view on top of change_log; the in-process Watcher (changeWatcher
	// above) is the foundation for a future /watch SSE push endpoint.
	changeLogHandler := handler.NewChangeLogHandler(scanQueries, dbConn)
	changeWatchHandler := handler.NewChangeWatchHandler(changeWatcher, slog.Default())
	registerChangeRoutes(r, scopeResolver, changeLogHandler, changeWatchHandler)

	registerDiscoveryRoutes(r, discSvcForStatus)

	// --- Scanner background services (v2) ---
	// Retention sweeper prunes all high-volume detail tables (heartbeat_results,
	// scan_results, scan_task_runs, audit_logs, notification_log,
	// service_evidence) on a single ticker, each with its own retention window.
	// Defaults & scanner.retention_days back-compat are applied in
	// config.normalizeRetention, so cfg.Retention is fully populated here.
	cleanupSvc := scannerv2cleanup.New(scanQueries, hbStore.Queries(), hbStore.DB(), dbConn, cfg.Retention)
	cleanupSvc.Start(context.Background())

	// Config-backup sweep (#137): fetches running-configs over SSH for devices
	// with a bound SSH credential. Opt-in (scanner.config_backup.enabled), needs
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

	// Probe engine (拨测): interval scheduler for external targets. Re-reads
	// enabled targets every tick, so no notify wiring from the CRUD service.
	probeEngine.Start(context.Background())
	registerAuditLogRoutes(r, auditHandler, exportHandler)

	// Device system routes
	deviceSystemRepo := service.NewDeviceSystemRepository(dbConn)
	deviceSystemSvc := service.NewDeviceSystemService(deviceSystemRepo)
	deviceSystemHandler := handler.NewDeviceSystemHandler(deviceSystemSvc)
	registerDeviceSystemRoutes(r, scopeResolver, dbConn, deviceSystemHandler)

	registerDeviceNeighborRoutes(r, scopeResolver, dbConn, neighborHandler)

	registerDeviceCertificateRoutes(r, scopeResolver, dbConn, tlsCertHandler)

	registerDeviceConfigRoutes(r, scopeResolver, dbConn, deviceConfigHandler)

	registerTopologyRoutes(r, scopeResolver, topologyHandler)

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
	registerDocumentRoutes(r, docHandler)

	// Heartbeat routes
	go heartbeatSvc.Start(context.Background())
	heartbeatHandler := handler.NewHeartbeatHandler(heartbeatSvc)

	registerDeviceHeartbeatRoutes(r, scopeResolver, dbConn, exportHandler, heartbeatHandler)
	// Fingerprint coverage report + rule-draft generation (#282). Read-only
	// analytics over scan_attributes + collected evidence; the draft POST is
	// a pure computation (returns YAML text, persists nothing).
	fingerprintSvc := service.NewFingerprintReportService(db.New(dbConn), dbConn)
	fingerprintHandler := handler.NewFingerprintHandler(fingerprintSvc)
	registerFingerprintRoutes(r, scopeResolver, fingerprintHandler)

	// Dashboard routes
	dashSvc := service.NewDashboardService(dbConn, cfg)
	dashHandler := handler.NewDashboardHandler(dashSvc)
	registerDashboardRoutes(r, scopeResolver, dashHandler)

	// Device-Document linking routes
	linkHandler := handler.NewLinkHandler(dbConn, auditRepo)
	registerDeviceDocumentRoutes(r, scopeResolver, dbConn, linkHandler)

	// Notification service, dispatcher, and handler
	notificationSvc := service.NewNotificationService(db.New(notifyDB))
	notificationDispatcher := notification.NewDispatcher(db.New(notifyDB), nil)
	notificationDispatcher.Start(context.Background())
	notificationHandler := handler.NewNotificationHandler(notificationSvc, notificationDispatcher, auditRepo)

	// Notification rule engine (#139): subscribes to changedetect.Watcher and
	// dispatches matching rules via notificationDispatcher. Shares the same
	// changeWatcher singleton as the /changes/watch SSE handler (independent
	// subscriber channels). Started here; stopped in the shutdown cleanup below.
	ruleEngine := notification.NewRuleEngine(scanQueries, changeWatcher, notificationDispatcher, slog.Default())
	ruleEngine.Start(context.Background())

	registerNotificationRoutes(r, notificationHandler)

	// Prometheus metrics + HTTP service discovery are PUBLIC: Prometheus
	// scrapes these endpoints without credentials, and they leak no secrets
	// (metrics are aggregate counters; SD exposes only device IPs/labels
	// that the scanner already published). Keep them out of RequireAuth/Admin.
	// prometheus.metrics_path (#239): previously defined in config but the
	// mount was hard-coded, silently ignoring the setting. Fall back to the
	// default for empty/malformed values (must be an absolute path).
	metricsPath := cfg.Prometheus.MetricsPath
	if metricsPath == "" || metricsPath[0] != '/' {
		metricsPath = "/metrics"
	}
	r.Handle(metricsPath, handler.MetricsHandler())
	sdHandler := handler.NewSDHandler(dbConn, deviceSystemRepo)
	r.Get("/sd", sdHandler.ServeHTTP)

	// Device gauges refresh on a 60s ticker (#333): they are Reset+Set
	// snapshots of DB state and seeding only at process start froze them at the
	// process-start snapshot, SQL-side cleanups and post-start discoveries
	// both drifted the counts until restart. Cancelled in the cleanup
	// closure below (before db.Close()).
	deviceMetricsCtx, deviceMetricsCancel := context.WithCancel(context.Background())
	go handler.StartDeviceMetricsRefresher(deviceMetricsCtx, dbConn, 60*time.Second)
	// SPA handler, serves embedded frontend
	spaHandler := handler.NewSPAHandler()
	r.Mount("/", spaHandler)

	return r, heartbeatSvc, func() {
		// Stop the vantage probe dispatch ticker (goroutine leak otherwise).
		// Guarded: the cleanup func is tolerates double calls, closing a
		// closed channel would panic on the second call.
		select {
		case <-probeDispatchStop:
			// already stopped
		default:
			close(probeDispatchStop)
		}
		// Stop the device-metrics refresher BEFORE the DB close, its tick
		// runs aggregate COUNTs against dbConn (#333).
		deviceMetricsCancel()
		if demoActivity != nil {
			demoActivity.Stop()
		}
		if scanScheduler != nil {
			scanScheduler.Stop()
		}
		// Stop the probe engine (拨测) BEFORE the DB close，an in-flight probe
		// writes probe_results / probe_tls_certs and must not race db.Close().
		// Stop() cancels the tick loop and waits for the in-flight tick.
		probeEngine.Stop()
		// Stop the lease sweeper BEFORE the DB close, its sweepOnce runs
		// UPDATE devices + recordDeviceLost (change_log INSERT) and must not
		// race db.Close(). Cancel unblocks an in-flight sweep's ctx-aware DB
		// calls, then Stop() waits for the goroutine to fully exit. (#163)
		leaseSweepCancel()
		leaseSweeper.Stop()
		// Stop the reconciliation job BEFORE the DB close, its scan reads
		// devices/networks and must not race db.Close().
		reconcileCancel()
		reconciler.Stop()
		// Stop the passive discovery sources + coordinator BEFORE the DB close;
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
		// Stop the rule engine BEFORE the dispatcher, it holds a Watcher
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
