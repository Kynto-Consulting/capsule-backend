package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	goredis "github.com/redis/go-redis/v9"
	"github.com/kynto/capsule/backend/internal/access"
	"github.com/kynto/capsule/backend/internal/authz"
	authzwire "github.com/kynto/capsule/backend/internal/authz/wire"
	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/ciwake"
	eventswire "github.com/kynto/capsule/backend/internal/gitevents/wire"
	"github.com/kynto/capsule/backend/internal/environments"
	"github.com/kynto/capsule/backend/internal/gitprotect"
	"github.com/kynto/capsule/backend/internal/gittokens"
	"github.com/kynto/capsule/backend/internal/netaccess"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/recovery"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/security"
	"github.com/kynto/capsule/backend/internal/server"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/service"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if dsn := os.Getenv("SENTRY_DSN"); dsn != "" {
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              dsn,
			Release:          version,
			Environment:      cfg.Env,
			TracesSampleRate: 0.1,
		}); err != nil {
			logger.Warn("sentry init failed", "error", err)
		} else {
			logger.Info("sentry initialized")
			defer sentry.Flush(2 * time.Second)
		}
	}

	if cfg.LogLevel == "debug" {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	logger.Info("starting capsule server",
		"version", version,
		"commit", commit,
		"build_date", buildDate,
		"env", cfg.Env,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := repository.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// `server fn-node <name>`: registers a work node of functions and prints its capnode_ token once (docs/vpn-connector.md).
	if len(os.Args) == 3 && os.Args[1] == "fn-node" {
		tok, err := (&fn.PGStore{Pool: pool}).CreateNode(ctx, os.Args[2])
		if err != nil {
			logger.Error("could not register node", "error", err)
			os.Exit(1)
		}
		fmt.Println(tok)
		return
	}

	userRepo       := repository.NewUserRepository(pool)
	orgRepo        := repository.NewOrgRepository(pool)
	projRepo       := repository.NewProjectRepository(pool)
	envVarRepo     := repository.NewEnvVarRepository(pool, cfg.SecretKey)
	orgEnvVarRepo  := repository.NewOrgEnvVarRepository(pool, cfg.SecretKey)
	deploymentRepo := repository.NewDeploymentRepository(pool, cfg.SecretKey)
	dbRepo         := repository.NewDatabaseRepository(pool)
	domainRepo     := repository.NewDomainRepository(pool)
	apiTokenRepo   := repository.NewAPITokenRepository(pool)
	settingsRepo   := repository.NewSettingsRepository(pool)
	workerRepo     := repository.NewWorkerRepository(pool)
	cronJobRepo    := repository.NewCronJobRepository(pool)
	execLogRepo    := repository.NewExecutionLogRepository(pool)
	emailLogRepo   := repository.NewEmailLogRepository(pool)
	authSvc        := service.NewAuthService(userRepo, settingsRepo, cfg.SecretKey, cfg.JWTAccessTTL, cfg.JWTRefreshTTL, logger)

	var cacheStore domain.CacheStore
	var redisRawClient *goredis.Client
	redisCache, err := repository.NewRedisCache(cfg.RedisURL)
	if err != nil {
		logger.Warn("redis unavailable; cache + distributed rate limiting disabled", "error", err)
	} else {
		cacheStore = redisCache
		redisRawClient = redisCache.Client()
	}

	awsCtx, awsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer awsCancel()
	awsClients, err := awsclient.New(awsCtx, cfg.AWSRegion,
		os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), cfg.AWSAccountID)
	if err != nil {
		logger.Warn("AWS clients unavailable", "error", err)
		awsClients = nil
	}

	// Per-database network access: reconciler over the app host's security group.
	accessRepo := repository.NewDatabaseAccessRepository(pool)
	networkRepo := repository.NewProjectNetworkRepository(pool)
	var accessApplier handlers.AccessApplier // stays a true nil when not configured (API answers 501)
	var portsFirewall service.PortsFirewall   // same reconciler (shared lock); true nil when not configured
	if awsClients != nil && awsClients.EC2 != nil {
		if rec := netaccess.NewReconciler(netaccess.AWSAdapter{Client: awsClients.EC2}, cfg.AppSecurityGroupID); rec != nil {
			accessApplier = rec
			portsFirewall = rec
			go func() {
				// Recover from drift: re-apply every stored rule, revoke owned rules of deleted databases.
				sctx, scancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer scancel()
				desired, err := accessRepo.ListDesired(sctx)
				if err != nil {
					logger.Warn("database access startup reconcile: listing rules failed", "error", err)
					return
				}
				items := make([]netaccess.Desired, 0, len(desired))
				for _, d := range desired {
					items = append(items, netaccess.Desired{DBID: d.DatabaseID, Port: d.Port, CIDR: d.CIDR})
				}
				if err := rec.SyncAll(sctx, items); err != nil {
					logger.Warn("database access startup reconcile failed", "error", err)
					return
				}
				logger.Info("database access rules reconciled", "rules", len(items))
			}()
		}
	}
	if accessApplier == nil {
		logger.Info("database network access API disabled (APP_SECURITY_GROUP_ID not set)")
	}

	// Worker runs with a cancellable context so graceful shutdown waits for
	// in-flight deployments to finish before the process exits.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	fargateConfig := service.FargateConfig{
		Cluster:          cfg.ECSCluster,
		Subnets:          splitComma(cfg.ECSSubnets),
		SecurityGroup:    cfg.ECSSecurityGroup,
		ExecutionRoleARN: cfg.ECSExecutionRoleARN,
		ALBListenerARN:   cfg.ALBListenerARN,
		VpcID:            cfg.VpcID,
		AppsDomain:       cfg.AppsDomain,
		ECRRegistry:      cfg.ECRRegistry,
	}
	deployWorker := service.NewDeployWorker(deploymentRepo, pool, awsClients, cfg.ArtifactsBucket, fargateConfig, logger, cfg.SecretKey)
	// Health checks + automatic rollback, build limits (CAPSULE_BUILD_*), scheduled docker cleanup.
	deployWorker.WithDeployConfig(service.LoadDeployConfig()).WithHealthStores(deploymentRepo, projRepo)
	connAuditRepo := repository.NewConnAuditRepository(pool)
	deployWorker.SetConnAudit(connAuditRepo) // report of non-routed internal connections (policy warn|strict|off per project)
	go deployWorker.RunCleanupLoop(workerCtx)
	portsSvc := wirePorts(cfg, logger, pool, deployWorker, portsFirewall)
	workerDone := make(chan struct{})
	go func() {
		deployWorker.Run(workerCtx)
		close(workerDone)
	}()

	// Put app containers without traffic to sleep (CAPSULE_IDLE_SLEEP_HOURS, default 12).
	go handlers.RunIdleReaper(workerCtx, logger)

	// Git auto-deploy + PR previews (webhook receiver, preview lifecycle, TTL reaper).
	gitHandler := wireGit(workerCtx, cfg, logger, pool, projRepo, orgRepo, deploymentRepo, awsClients, fargateConfig)

	// Catch OS signals so we cancel the worker before the process exits.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutdown signal received, stopping worker")
		workerCancel()
		select {
		case <-workerDone:
		case <-time.After(30 * time.Second):
			logger.Warn("worker did not finish in time, forcing shutdown")
		}
	}()

	// OpenID Connect provider (Forgejo login etc.). A failure here disables only OIDC.
	var oidcSvc *oidc.Service
	oidcCtx, oidcCancel := context.WithTimeout(context.Background(), 15*time.Second)
	oidcKeys, oidcErr := oidc.LoadKeySet(oidcCtx, settingsRepo, cfg.SecretKey, cfg.OIDCSigningKey, cfg.OIDCPreviousSigningKey)
	oidcCancel()
	if oidcErr != nil {
		logger.Error("OIDC provider disabled: signing key unavailable", "error", oidcErr)
	} else {
		oidcSvc = oidc.New(oidc.Config{Issuer: cfg.OIDCIssuer, FrontendURL: cfg.FrontendURL},
			repository.NewOIDCRepository(pool), userRepo, oidcKeys, logger)
		logger.Info("OIDC provider enabled", "issuer", cfg.OIDCIssuer, "kid", oidcKeys.Active.KID)
	}

	projectMemberRepo := repository.NewProjectMemberRepository(pool)
	authzSvc := authz.New(projectMemberRepo)
	// authz-engine:wiring begin
	// New permission engine (docs/permissions): CAPSULE_AUTHZ_MODE v1 (default) | shadow | v2. v1 does not consult it.
	// Seeds the system templates (the migrations already ran in NewPool).
	if authzRT, err := authzwire.Start(workerCtx, logger, pool); err != nil {
		logger.Error("permission engine unavailable; decisions stay on the legacy path", "error", err)
	} else {
		authzRT.Attach(authzSvc)
		middleware.SetTokenGate(authzRT.Gate(server.RouteTable()))
		handlers.WireAccess(access.New(authzRT.Store, authzRT.Engine, logger), logger) // P4: templates, groups, assignments, /me/permissions, simulator
		logger.Info("permission engine ready", "mode", string(authzRT.Global))
	}
	// authz-engine:wiring end
	if oidcSvc != nil {
		// Project roles travel as "project:<org>/<project>:<role>" group claims.
		oidcSvc.ExtraGroups = authzSvc.ProjectGroups
	}
	if gitHandler != nil {
		gitHandler.SetAuthorizer(gitAuthorizer{svc: authzSvc})
	}
	// Core Git (Forgejo): provisioning, team sync, Git views, API previews, capabilities.
	gitCoreHandler := wireGitCore(workerCtx, cfg, logger, pool, gitHandler, projRepo, orgRepo, deploymentRepo, projectMemberRepo, oidcSvc != nil)

	// git-capsule:wiring begin
	// Git Capsule wiring. A1 owns the shared Core: gitcore.Wire(workerCtx, logger, cacheStore)
	// builds it from CAPSULE_GIT_* and publishes it (gitcore.Shared()). Add it here, then
	// one line per package, alphabetical by id: `<pkg>.Wire<Pkg>(workerCtx, ...)`.
	var gitCoreCache gitcore.Cache
	if cacheStore != nil {
		gitCoreCache = cacheStore
	}
	gitcore.Wire(workerCtx, logger, gitCoreCache)
	wireGitSync(workerCtx, logger, pool, cfg.SecretKey, orgRepo, projRepo, projectMemberRepo, userRepo, oidcSvc, authzSvc, gitHandler) // A2
	gitprotect.WireGitProtect(workerCtx, logger, repository.NewBranchProtectionRepository(pool)) // A4: branch protection rules, drift reconciler
	eventswire.Wire(workerCtx, logger, pool, cfg.SecretKey, cfg.FrontendURL, awsClients) // A5: event bus, notifications, outbound webhooks, inbound webhook sink
	environments.WireEnvironments(workerCtx, logger, environments.Deps{Store: repository.NewEnvironmentRepository(pool), Deployments: deploymentRepo, Users: userRepo, Authz: authzSvc, Admins: projectMemberRepo}) // A6: environments, promotions, approvals, queue/expiry loop (after A5: uses the shared event bus)
	handlers.WireGitTokens(workerCtx, logger, handlers.GitTokensWiring{Store: repository.NewGitAccessRepository(pool), Users: userRepo, Orgs: orgRepo, Projects: projRepo, Authz: authzSvc, APITokens: apiTokenRepo, UsernameTaken: repository.NewOIDCRepository(pool), Identity: gittokens.GitsyncIdentity{IDs: sharedGitIdentities, Users: userRepo, Fallback: gittokens.NameRules{Users: userRepo, Taken: repository.NewOIDCRepository(pool)}}}) // A7: login = the one A2 (gitsync.Identities) registers
	security.WireSecurity(workerCtx, logger, repository.NewSecurityRepository(pool), cfg.SecretKey) // B7: SARIF alerts, policy and capsule/security check, suppressions, Renovate state (after A5: subscribes to the event bus)
	wireGitReview(workerCtx, logger, pool, cfg.SecretKey, orgRepo, projRepo, projectMemberRepo, authzSvc) // B8: CODEOWNERS, capsule/policy, auto-merge worker, review janitor (after A2 and A5)
	wireGitImport(workerCtx, logger, pool, cfg.SecretKey, projRepo) // C1: GitHub import and push mirror (after A2: reconciles the teams of imported projects)
	wireGitC2(workerCtx, logger, pool, cfg.FrontendURL, awsClients) // C2: audit read/retention, activity, insights, digest, expiry notices (after A5; A7 Notifier: gitinsights.SharedTokenNotifier())
	recovery.WireRecovery(workerCtx, logger, repository.NewRecoveryRepository(pool), cfg.SecretKey, awsClients) // C3: total recovery (plan/apply/verify), enabled with CAPSULE_RECOVERY_ENABLED
	// git-capsule:wiring end

	// ciwake:wiring begin
	// CI runner scale-to-zero: starts the stopped runner EC2 on push/PR (after A5: needs the event bus). Off without CAPSULE_CI_RUNNER_INSTANCE_ID.
	if _, err := ciwake.Wire(logger, awsClients); err != nil {
		logger.Warn("ciwake not wired", "error", err)
	}
	// ciwake:wiring end

	// gateway:wiring begin
	// Universal gateway control plane (docs/gateway/PLAN.md 5): one line per gateway package.
	wireGateway(workerCtx, logger, pool, cfg.TCPHost, orgRepo, projRepo, userRepo, apiTokenRepo, dbRepo, accessRepo, networkRepo, authzSvc) // G3: /internal/gateway/*, user API, port pool and sweeper
	// gateway:wiring end

	backupsSvc := wireBackups(workerCtx, cfg, logger, pool, awsClients, projRepo, dbRepo)
	objstoreDeps := wireObjstore(cfg, logger, pool, backupsSvc)

	ingressCfg := wireIngress(cfg, logger)
	// VPN Connector + functions in the tunnel (docs/vpn-connector.md): the backend only plans, claims and audits; the work node executes.
	vpnSvc := &vpn.Service{Store: &vpn.PGStore{Pool: pool}, SecretKey: cfg.SecretKey}
	fnApiBase := os.Getenv("CAPSULE_API_URL")
	if fnApiBase == "" && cfg.PublicHost != "" {
		fnApiBase = "https://" + cfg.PublicHost
	}
	fnSvc := &fn.Service{Store: &fn.PGStore{Pool: pool}, VPN: vpnSvc, APIBase: fnApiBase, DBs: fn.NewDBResolver(dbRepo, cfg.SecretKey)}
	if objstoreDeps != nil {
		fnSvc.Storage = fnStorageResolver(objstoreDeps, dbRepo) // ctx.storage on Capsule's own object store
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-t.C:
				if err := fnSvc.Tick(workerCtx); err != nil {
					logger.Error("fn scheduler tick failed", "error", err)
				}
			}
		}
	}()

	srv := server.New(cfg, logger, version, server.Deps{
		Authz:              authzSvc,
		ProjectMembers:     projectMemberRepo,
		AuthSvc:            authSvc,
		OrgRepo:            orgRepo,
		UserRepo:           userRepo,
		ProjRepo:           projRepo,
		EnvVarRepo:         envVarRepo,
		OrgEnvVarRepo:      orgEnvVarRepo,
		DeploymentRepo:     deploymentRepo,
		CacheStore:         cacheStore,
		RedisClient:        redisRawClient,
		DatabaseRepo:       dbRepo,
		DomainRepo:         domainRepo,
		APITokenRepo:       apiTokenRepo,
		AWSClients:         awsClients,
		ALBDNSName:         cfg.ALBDNSName,
		Ingress:            ingressCfg,
		DBSubnetGroup:      cfg.DBSubnetGroup,
		RDSSecurityGroupID: cfg.RDSSecurityGroupID,
		PublicHost:         cfg.PublicHost,
		DBHost:             cfg.DBHost,
		SecretKey:          cfg.SecretKey,
		ArtifactsBucket:    cfg.ArtifactsBucket,
		WorkerRepo:         workerRepo,
		CronJobRepo:        cronJobRepo,
		ExecLogRepo:        execLogRepo,
		EmailLogRepo:       emailLogRepo,
		AccessRepo:         accessRepo,
		NetworkRepo:        networkRepo,
		AccessApplier:      accessApplier,
		PortsSvc:           portsSvc,
		ConnAudit:          connAuditRepo,
		FargateConfigured:  awsClients != nil && fargateConfig.IsConfigured(),
		Git:                gitHandler,
		Backups:            backupsSvc,
		Objstore:           objstoreDeps,
		GitCore:            gitCoreHandler,
		OIDC:               oidcSvc,
		VPN:                vpnSvc,
		Fn:                 fnSvc,
	})
	if err := srv.Run(); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}
