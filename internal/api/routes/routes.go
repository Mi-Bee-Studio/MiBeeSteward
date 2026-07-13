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

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/repository"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/notification"
	scannerv2cleanup "mibee-steward/internal/service/scannerv2/cleanup"
	scannerv2discovery "mibee-steward/internal/service/scannerv2/discovery"
	scannerv2ebpf "mibee-steward/internal/service/scannerv2/ebpf"
	scannerv2engine "mibee-steward/internal/service/scannerv2/engine"
	scannerv2probe "mibee-steward/internal/service/scannerv2/probe"
	scannerv2runner "mibee-steward/internal/service/scannerv2/runner"
	scannerv2scheduler "mibee-steward/internal/service/scannerv2/scheduler"
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
	auditRepo := repository.NewAuditRepository(dbConn)

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
	// RealIP is deprecated in chi (IP-spoofing risk: it trusts X-Forwarded-For
	// unconditionally). We keep it because this service is designed to sit behind
	// a trusted reverse proxy (nginx — see deploy/) that overwrites the header;
	// direct exposure to untrusted networks is not a supported deployment.
	// TODO(security): replace with a trusted-proxy-aware RealIP once a
	// trusted_proxies config knob lands.
	r.Use(chimw.RealIP) //nolint:staticcheck // SA1019: trusted-proxy deployment, see note above
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

	// Admin-only user list
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Get("/", userHandler.ListUsers)
		r.Post("/batch-delete", batchHandler.BatchDeleteUsers)
		r.Post("/{id}/reset-password", userHandler.AdminResetPassword)
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
	exportHandler := handler.NewExportHandler(service.NewExportService(db.New(dbConn), hbStore.Queries()))

	// Device routes
	deviceRepo := repository.NewDeviceRepository(dbConn)
	deviceSvc := service.NewDeviceService(deviceRepo, heartbeatSvc)
	deviceHandler := handler.NewDeviceHandler(deviceSvc)
	r.Route("/api/v1/devices", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/export", exportHandler.ExportDevices)
			r.Get("/", deviceHandler.List)
			r.Get("/stats", deviceHandler.GetStats)
			r.Get("/{id}", deviceHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", deviceHandler.Create)
			r.Put("/{id}", deviceHandler.Update)
			r.Delete("/{id}", deviceHandler.Delete)
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
	// update/delete are admin-only.
	networkHandler := handler.NewNetworkHandler(scanQueries, dbConn)
	r.Route("/api/v1/networks", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", networkHandler.List)
		r.With(middleware.RequireAdmin).Post("/", networkHandler.Create)
		r.With(middleware.RequireAdmin).Put("/{id}", networkHandler.Update)
		r.With(middleware.RequireAdmin).Delete("/{id}", networkHandler.Delete)
	})

	// L2 topology — neighbors per device (detail page) + the whole-network
	// topology graph (nodes + edges). Read-only; any logged-in user.
	neighborHandler := handler.NewNeighborHandler(scanQueries)
	topologyHandler := handler.NewTopologyHandler(scanQueries)

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
		scannerPortSpec = "22,21,23,25,53,80,110,143,389,443,445,554,631,636,8554,1433," +
			"3306,3389,5432,5900,6379,8000,8080,8081,8443,8888,9000,9090,9100,9104," +
			"9113,9121,9187,9200,9443,11211,27017,161"
	}
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
		RouterARP: scannerv2probe.RouterARPConfig{
			Routers:   cfg.Scanner.RouterARP.Routers,
			Community: routerCommunity(cfg.Scanner),
			Timeout:   time.Duration(routerTimeout(cfg.Scanner)) * time.Second,
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

	// Change detection (Phase 3): the center records device_added/changed/lost
	// events to change_log + pushes in-process Watcher subscribers. The agent
	// does NOT set this (change detection is a center concern; agents only
	// forward raw HostReports). The watcher is the foundation for a future
	// /watch SSE endpoint (Step 4 surfaces a query API on top of change_log).
	changeWatcher := changedetect.NewWatcher(slog.Default())
	changeRecorder := changedetect.NewDBRecorder(scanQueries, changeWatcher, slog.Default())
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
		// router_arp: the widest-coverage source. One SNMP Walk per router per
		// interval; no-op when no routers are configured.
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
		discSvc.SetSources(activeSources)
		slog.Info("scannerv2 passive discovery ready",
			"interval", interval.String(),
			"sources", activeSources,
			"trigger_identify", cfg.Scanner.Discovery.TriggerIdentify)
	}

	// Scheduler: cron-driven scan tasks. The ScanFunc delegates to the runner.
	scanScheduler, schedErr := scannerv2scheduler.New(scanQueries, dbConn,
		func(ctx context.Context, taskID int64, targets string, timeout time.Duration, concurrentHosts int) {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("scan_func_panic", "task_id", taskID, "panic", r)
				}
			}()
			scanRunner.Run(ctx, taskID, targets, timeout, concurrentHosts, cfg.Scanner.PersistRawEvidence)
		}, slog.Default())
	if schedErr != nil {
		slog.Error("failed to create scan scheduler", "error", schedErr)
		scanScheduler = nil
	}

	scanTaskService := scannerv2task.New(scanQueries, scanScheduler)
	scannerHandler := handler.NewScannerHandler(v2Engine, scanRunner)
	scannerTaskHandler := handler.NewScannerTaskHandler(scanTaskService)
	scannerResultHandler := handler.NewScannerResultHandler(scanQueries)
	r.Route("/api/v1/scanner", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		// Rate-limited scan trigger endpoints (per-IP, 10/min default)
		r.Group(func(r chi.Router) {
			r.Use(scanLimiter.Middleware)
			r.Post("/scan", scannerHandler.Scan)
			r.Post("/tasks/{id}/trigger", scannerTaskHandler.TriggerTask)
		})
		// Non-rate-limited scanner routes
		r.Post("/add-devices", scannerHandler.AddDevices)
		// Task CRUD
		r.Post("/tasks", scannerTaskHandler.CreateTask)
		r.Get("/tasks", scannerTaskHandler.ListTasks)
		r.Get("/tasks/{id}", scannerTaskHandler.GetTask)
		r.Put("/tasks/{id}", scannerTaskHandler.UpdateTask)
		r.Delete("/tasks/{id}", scannerTaskHandler.DeleteTask)
		r.Get("/tasks/{id}/runs", scannerTaskHandler.GetTaskRuns)
		r.Get("/tasks/{id}/results", scannerTaskHandler.GetTaskResults)
		r.Post("/tasks/{id}/cancel", scannerTaskHandler.CancelScanTask)
		// Results & runs
		r.Get("/results", scannerResultHandler.ListResults)
		r.Get("/results/{id}", scannerResultHandler.GetResult)
		r.Get("/runs", scannerResultHandler.ListRuns)
		r.Get("/runs/{id}", scannerResultHandler.GetRun)
		r.Get("/results/export", scannerResultHandler.ExportScanResults)
		r.Delete("/results", scannerResultHandler.BulkDeleteResults)
	})

	// --- Agent token management (distributed phase) ---
	// Admin-only CRUD for discovery-agent bearer tokens. The ingestion endpoint
	// (/agents/report below) authenticates via RequireAgentToken against this
	// table; this block is the management surface.
	agentAdminHandler := handler.NewAgentAdminHandler(scanQueries)
	r.Route("/api/v1/agents/tokens", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
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
	agentReportHandler := handler.NewAgentReportHandler(scanRunner)
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
	// view all commands (GET). Separate route group (RequireAdmin, not agent token).
	r.Route("/api/v1/agents/{agentId}/commands", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/", agentCommandHandler.Create)
	})
	r.With(middleware.RequireAdmin).Get("/api/v1/agents/commands/all", agentCommandHandler.ListAll)

	// --- Change history query (Phase 3) ---
	// GET /api/v1/changes returns the device_added/changed/lost event stream
	// written by the change-detection engine. Auth-gated (any logged-in user);
	// filterable by network_id / change_type / entity_type. This is the
	// queryable view on top of change_log; the in-process Watcher (changeWatcher
	// above) is the foundation for a future /watch SSE push endpoint.
	changeLogHandler := handler.NewChangeLogHandler(scanQueries)
	changeWatchHandler := handler.NewChangeWatchHandler(changeWatcher, slog.Default())
	r.Route("/api/v1/changes", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", changeLogHandler.List)
		r.Get("/watch", changeWatchHandler.Watch)
	})

	// Passive discovery status: runtime counters (events received, dedup hits,
	// identify triggers, devices recorded) + the last few discovery outcomes +
	// which sources are active. Auth-gated (any logged-in user). Returns
	// enabled=false when discovery is off or the service was never started.
	r.Route("/api/v1/discovery", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/status", handler.DiscoveryStatusHandler(discSvcForStatus))
	})

	// --- Scanner background services (v2) ---
	// Retention sweeper prunes all high-volume detail tables (heartbeat_results,
	// scan_results, scan_task_runs, audit_logs, notification_log,
	// service_evidence) on a single ticker, each with its own retention window.
	// Defaults & scanner.retention_days back-compat are applied in
	// config.normalizeRetention, so cfg.Retention is fully populated here.
	cleanupSvc := scannerv2cleanup.New(scanQueries, hbStore.Queries(), cfg.Retention)
	cleanupSvc.Start(context.Background())

	if scanScheduler != nil {
		scanScheduler.Start(context.Background())
	}
	// Audit log routes (admin only)
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Get("/api/v1/audit-logs", auditHandler.List)
		r.Get("/api/v1/audit-logs/export", exportHandler.ExportAuditLogs)
	})

	// Device system routes
	deviceSystemRepo := repository.NewDeviceSystemRepository(dbConn)
	deviceSystemSvc := service.NewDeviceSystemService(deviceSystemRepo)
	deviceSystemHandler := handler.NewDeviceSystemHandler(deviceSystemSvc)
	r.Route("/api/v1/devices/{id}/systems", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", deviceSystemHandler.ListByDevice)
			r.Get("/{systemId}", deviceSystemHandler.Get)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", deviceSystemHandler.Create)
			r.Put("/{systemId}", deviceSystemHandler.Update)
			r.Delete("/{systemId}", deviceSystemHandler.Delete)
		})
	})

	// Device L2 neighbors (Bridge-MIB / LLDP / CDP / ARP) — read-only, any
	// logged-in user. Feeds the detail-page Neighbors panel.
	r.Route("/api/v1/devices/{id}/neighbors", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", neighborHandler.ListByDevice)
	})

	// Network-level topology graph — all devices (nodes) + all neighbor edges.
	// Read-only, any logged-in user. Feeds the /topology page.
	r.Route("/api/v1/topology", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
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
			r.Use(middleware.RequireAuth)
			r.Get("/", docHandler.List)
			r.Get("/{id}", docHandler.Get)
			r.Get("/{id}/download", docHandler.Download)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
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
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", heartbeatHandler.ListConfigs)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", heartbeatHandler.CreateConfig)
		})
	})

	// Heartbeat config CRUD
	r.Route("/api/v1/heartbeat-configs", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Put("/{id}", heartbeatHandler.UpdateConfig)
		r.Delete("/{id}", heartbeatHandler.DeleteConfig)
	})

	// Heartbeat results
	r.Route("/api/v1/devices/{id}/heartbeat-results", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/export", exportHandler.ExportHeartbeatResults)
		r.Get("/", heartbeatHandler.ListResults)
	})

	// Heartbeat history and stats
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/api/v1/devices/{id}/heartbeat-history", heartbeatHandler.ListHistory)
		r.Get("/api/v1/devices/{id}/heartbeat-stats", heartbeatHandler.GetStats)
	})
	// Dashboard routes
	dashSvc := service.NewDashboardService(dbConn, cfg)
	dashHandler := handler.NewDashboardHandler(dashSvc)
	r.Route("/api/v1/dashboard", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/configs", dashHandler.ListConfigs)
			r.Get("/overview", dashHandler.Overview)
			r.Get("/query", dashHandler.Query)
			r.Get("/query_range", dashHandler.QueryRange)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/configs", dashHandler.CreateConfig)
			r.Put("/configs/{id}", dashHandler.UpdateConfig)
			r.Delete("/configs/{id}", dashHandler.DeleteConfig)
		})
	})

	// Device-Document linking routes
	linkHandler := handler.NewLinkHandler(dbConn, auditRepo)
	r.Route("/api/v1/devices/{id}/documents", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth)
			r.Get("/", linkHandler.GetDeviceDocuments)
		})
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Post("/", linkHandler.LinkDocument)
			r.Delete("/{docId}", linkHandler.UnlinkDocument)
		})
	})
	r.Route("/api/v1/documents/{id}/devices", func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/", linkHandler.GetDocumentDevices)
	})

	// Notification service, dispatcher, and handler
	notificationSvc := service.NewNotificationService(db.New(dbConn))
	notificationDispatcher := notification.NewDispatcher(db.New(dbConn), nil)
	notificationDispatcher.Start(context.Background())
	notificationHandler := handler.NewNotificationHandler(notificationSvc, notificationDispatcher, auditRepo)

	// Notification channel routes (admin only)
	r.Route("/api/v1/notification/channels", func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Post("/", notificationHandler.CreateChannel)
		r.Get("/", notificationHandler.ListChannels)
		r.Get("/{id}", notificationHandler.GetChannel)
		r.Put("/{id}", notificationHandler.UpdateChannel)
		r.Delete("/{id}", notificationHandler.DeleteChannel)
		r.Post("/{id}/test", notificationHandler.TestChannel)
	})

	// Notification log routes (admin only)
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Get("/api/v1/notification/logs", notificationHandler.ListNotificationLogs)
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
		// race db.Close().
		leaseSweepCancel()
		// Stop the passive discovery sources + coordinator BEFORE the DB close —
		// the coordinator's known-host pre-check and the sources' walks hold
		// open DB/SNMP handles that must not race db.Close().
		if discCancel != nil {
			discCancel()
		}
		discSvc.Stop()
		cleanupSvc.Stop()
		// Stop the notification dispatcher's worker goroutines too. Without
		// this, the 3 workers (and their *db.Queries handle) outlive graceful
		// shutdown and race against db.Close() in main.go.
		notificationDispatcher.Stop()
	}
}

// chunkSlice splits a slice into chunks of the given size.
func chunkSlice[S any](items []S, batchSize int) [][]S {
	if batchSize <= 0 {
		return [][]S{items}
	}
	var chunks [][]S
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}
	return chunks
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
