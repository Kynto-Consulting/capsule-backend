package server

import (
	"github.com/google/uuid"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/redis/go-redis/v9"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/backup"
	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/connaudit"
	"github.com/kynto/capsule/backend/internal/domain"
	gwapi "github.com/kynto/capsule/backend/internal/gateway/api"
	"github.com/kynto/capsule/backend/internal/ingress"
	"github.com/kynto/capsule/backend/internal/gitsync"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/service"
	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn/gateway"
	"github.com/kynto/capsule/backend/internal/vpn"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

type Deps struct {
	AuthSvc        domain.AuthService
	OrgRepo        domain.OrganizationRepository
	UserRepo       domain.UserRepository
	ProjRepo       domain.ProjectRepository
	EnvVarRepo     domain.EnvVarRepository
	OrgEnvVarRepo  domain.OrgEnvVarRepository
	DeploymentRepo domain.DeploymentRepository
	CacheStore     domain.CacheStore // optional; may be nil
	RedisClient    *redis.Client    // optional; used for distributed rate limiting

	DatabaseRepo       domain.DatabaseRepository
	DomainRepo         domain.DomainRepository
	APITokenRepo       domain.APITokenRepository
	WorkerRepo         domain.WorkerRepository
	CronJobRepo        domain.CronJobRepository
	ExecLogRepo        domain.ExecutionLogRepository
	EmailLogRepo       domain.EmailLogRepository
	AWSClients         *awsclient.Clients
	ALBDNSName         string
	Ingress            ingress.Config // zero value = ALB mode; ModeCaddy = no ALB (see internal/ingress)
	DBSubnetGroup      string
	RDSSecurityGroupID string
	PublicHost         string
	DBHost             string
	SecretKey          string
	ArtifactsBucket    string

	// Network access (all optional; nil disables the matching feature)
	AccessRepo    domain.DatabaseAccessRepository
	NetworkRepo   domain.ProjectNetworkRepository
	AccessApplier handlers.AccessApplier // nil => database access API answers 501
	PortsSvc      *service.PortsService   // nil => extra TCP ports API answers 501
	FargateConfigured bool            // true when the default deploy strategy resolves to Fargate (ports unsupported)

	// Git auto-deploy + PR previews (nil disables the routes)
	Git *handlers.GitHandler

	// Data backups (nil disables the routes)
	Backups *backup.Service
	// Capsule's own object store (nil: `capsule storage create` provisions AWS S3 buckets)
	Objstore *ObjstoreDeps

	// Core Git (Forgejo): repo provisioning, branches/commits/pulls views, API previews (nil disables the routes)
	GitCore *handlers.GitCoreHandler

	OIDC *oidc.Service // nil disables the OpenID Connect provider

	// Per-project permissions. Authz nil => organization roles only (open mode).
	// ProjectMembers nil => the members API answers 501.
	Authz          *authz.Service
	ProjectMembers authz.MemberStore

	// Deploy connection audit (nil: connection_warnings omitted, policy routes answer 501)
	ConnAudit connaudit.Store

	// VPN Connector + functions inside the tunnel (nil: the routes answer 501). docs/vpn-connector.md
	VPN *vpn.Service
	Fn  *fn.Service
	// FnRelay lets Lambda functions reach a tunnel through the work node (docs/vpn-connector.md, section 7). Optional.
	FnRelay *gateway.Relay
}

func newRouter(cfg *config.Config, logger *slog.Logger, version string, deps Deps) *chi.Mux {
	authHandler       := handlers.NewAuthHandler(deps.AuthSvc, deps.CacheStore)
	orgHandler        := handlers.NewOrgHandler(deps.OrgRepo)
	projectHandler    := handlers.NewProjectHandler(deps.ProjRepo, deps.OrgRepo)
	if hs, ok := deps.ProjRepo.(domain.ProjectHealthStore); ok {
		projectHandler.SetHealthStore(hs) // deploy health-check settings (PATCH health_*)
	}
	envVarHandler     := handlers.NewEnvVarHandler(deps.EnvVarRepo, deps.OrgRepo, deps.ProjRepo)
	orgEnvHandler     := handlers.NewOrgEnvHandler(deps.OrgEnvVarRepo, deps.OrgRepo)
	deploymentHandler := handlers.NewDeploymentHandler(deps.DeploymentRepo, deps.OrgRepo, deps.ProjRepo, deps.AWSClients, deps.ArtifactsBucket, logger)
	databaseHandler   := handlers.NewDatabaseHandler(
		deps.DatabaseRepo, deps.OrgRepo, deps.ProjRepo,
		deps.AWSClients, deps.SecretKey,
		deps.DBSubnetGroup, deps.RDSSecurityGroupID, firstNonEmpty(deps.DBHost, deps.PublicHost), logger,
	)
	accessHandler := handlers.NewDatabaseAccessHandler(
		deps.DatabaseRepo, deps.OrgRepo, deps.ProjRepo, deps.AccessRepo, deps.AccessApplier,
		firstNonEmpty(deps.DBHost, deps.PublicHost), os.Getenv("CAPSULE_DB_TLS_DIR"), deps.SecretKey, logger,
	)
	databaseHandler.SetOnDelete(accessHandler.Cleanup)
	portsHandler := handlers.NewProjectPortsHandler(deps.OrgRepo, deps.ProjRepo, deps.DeploymentRepo, deps.PortsSvc, deps.FargateConfigured, logger)
	projectHandler.SetOnDelete(portsHandler.Cleanup)
	allowlistCache := handlers.NewAllowlistCache(deps.NetworkRepo, 0)
	networkHandler := handlers.NewNetworkHandler(deps.OrgRepo, deps.ProjRepo, deps.NetworkRepo, allowlistCache)
	domainHandler := handlers.NewDomainHandler(
		deps.DomainRepo, deps.OrgRepo, deps.ProjRepo,
		deps.AWSClients, deps.ALBDNSName, logger,
	)
	domainHandler.SetIngress(deps.Ingress, nil)
	storageHandler := handlers.NewStorageHandler(
		deps.DatabaseRepo, deps.OrgRepo, deps.ProjRepo,
		deps.AWSClients, deps.SecretKey, logger,
	)
	if o := deps.Objstore; o != nil {
		storageHandler.SetObjstore(handlers.ObjstoreConfig{Store: o.Store, Repo: o.Repo, EnvVars: deps.EnvVarRepo, PublicEndpoint: o.PublicEndpoint, InternalEndpoint: o.InternalEndpoint, Region: o.Region})
		purgePorts := portsHandler.Cleanup
		projectHandler.SetOnDelete(func(id uuid.UUID) { purgePorts(id); storageHandler.CleanupProject(id) })
	}
	emailHandler := handlers.NewEmailHandler(
		deps.DatabaseRepo, deps.OrgRepo, deps.ProjRepo,
		deps.EmailLogRepo, deps.AWSClients, deps.SecretKey, logger,
	)
	aiHandler := handlers.NewAIHandler(
		deps.APITokenRepo, deps.OrgRepo, deps.ProjRepo, deps.DeploymentRepo,
		deps.AWSClients, logger, deps.AuthSvc, deps.CacheStore,
	)
	pricingHandler := handlers.NewPricingHandler()
	billingHandler := handlers.NewBillingHandler(deps.DatabaseRepo, deps.AWSClients)
	proxyHandler := handlers.NewProxyHandler(deps.OrgRepo, deps.ProjRepo, deps.DomainRepo, deps.DeploymentRepo, deps.ExecLogRepo, deps.AWSClients)
	if deps.NetworkRepo != nil {
		proxyHandler.SetAllowlist(allowlistCache)
	}
	workerHandler := handlers.NewWorkerHandler(deps.WorkerRepo, deps.OrgRepo, deps.ProjRepo, logger, deps.AWSClients)
	cronHandler := handlers.NewCronJobHandler(deps.CronJobRepo, deps.OrgRepo, deps.ProjRepo, deps.ExecLogRepo, logger, deps.AWSClients)
	membersHandler := handlers.NewOrgMembersHandler(deps.OrgRepo, deps.UserRepo)
	if deps.Objstore != nil {
		proxyHandler.SetObjstore(deps.Objstore.S3)
	}
	adminHandler    := handlers.NewAdminHandler(deps.UserRepo)
	apiTokenHandler := handlers.NewAPITokenHandler(deps.APITokenRepo, deps.OrgRepo, deps.ProjRepo)
	logsHandler := handlers.NewLogsHandler(deps.OrgRepo, deps.ProjRepo, deps.ExecLogRepo, logger)

	// Per-project authorization shared by every project-scoped handler.
	az := deps.Authz
	if az == nil {
		az = authz.New(authz.OrgOnlyStore{Orgs: deps.OrgRepo})
	}
	for _, h := range []interface{ SetAuthz(*authz.Service) }{
		projectHandler, envVarHandler, deploymentHandler, databaseHandler, accessHandler, portsHandler,
		networkHandler, domainHandler, storageHandler, emailHandler, workerHandler,
		cronHandler, logsHandler, apiTokenHandler,
	} {
		h.SetAuthz(az)
	}
	orgHandler.SetAccessModes(deps.ProjectMembers)
	deploymentHandler.SetConnAudit(deps.ConnAudit)
	deploymentHandler.SetECSUnavailable(deps.Ingress.Caddy() && !deps.FargateConfigured)
	vpnFnHandler := handlers.NewVPNFnHandler(deps.OrgRepo, deps.ProjRepo, deps.VPN, deps.Fn)
	vpnFnHandler.SetAuthz(az)
	vpnFnHandler.SetRelay(deps.FnRelay)
	connAuditHandler := handlers.NewConnAuditHandler(deps.OrgRepo, deps.ProjRepo, deps.ConnAudit)
	connAuditHandler.SetAuthz(az)
	var backupsHandler *handlers.BackupHandler
	projectMembersHandler := handlers.NewProjectMembersHandler(deps.OrgRepo, deps.ProjRepo, deps.ProjectMembers, az)

	if deps.Backups != nil {
		backupsHandler = handlers.NewBackupHandler(deps.OrgRepo, deps.ProjRepo, deps.Backups)
		backupsHandler.SetAuthz(az)
	}

	r := chi.NewRouter()
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"route not found"}}`))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(`{"error":{"code":"METHOD_NOT_ALLOWED","message":"method not allowed"}}`))
	})
	r.Use(middleware.RequestID)
	r.Use(middleware.CaptureRemoteAddr) // must run before RealIP (which trusts client headers)
	r.Use(chiMiddleware.RealIP)
	r.Use(middleware.InternalEdgeGuard) // /internal/* never carries a public client address (see its doc)
	r.Use(middleware.Logger(logger))
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.RateLimiterRedis(cfg.RateLimitRPS, cfg.RateLimitBurst, deps.RedisClient))
	r.Use(middleware.Metrics)
	corsHandler := cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSAllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "Idempotency-Key"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	// The OIDC provider routes set their own CORS headers (wildcard, no credentials).
	r.Use(func(next http.Handler) http.Handler {
		withCORS := corsHandler(next)
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if handlers.IsOIDCPath(req.URL.Path) {
				next.ServeHTTP(w, req)
				return
			}
			withCORS.ServeHTTP(w, req)
		})
	})

	// Custom domain middleware — intercept requests from non-platform hosts
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Internal paths are never custom-domain traffic (Next.js rewrites
			// arrive here with the Docker hostname, not the public domain).
			path := r.URL.Path
			if path == "/health" ||
				strings.HasPrefix(path, "/_proxy/") ||
				strings.HasPrefix(path, "/internal/") ||
				strings.HasPrefix(path, "/apps/") {
				next.ServeHTTP(w, r)
				return
			}

			host := r.Host
			// Strip port
			if i := strings.LastIndex(host, ":"); i >= 0 {
				host = host[:i]
			}
			// Custom domain: proxy ALL paths (including /api/*) to the container
			if host != "" &&
				!strings.HasSuffix(host, ".apps.tumi-ai.com") &&
				!strings.HasSuffix(host, ".tumi-ai.com") &&
				host != "localhost" &&
				host != "api.tumi-ai.com" {
				proxyHandler.ProxyByHost(w, r)
				return
			}
			// Platform domain: normal routing
			next.ServeHTTP(w, r)
		})
	})

	var oidcHandler *handlers.OIDCHandler
	if deps.OIDC != nil {
		oidcHandler = handlers.NewOIDCHandler(deps.OIDC, deps.OrgRepo)
		oidcHandler.MountPublic(r, middleware.RateLimiter(10, 30))
	}

	r.Get("/health", handlers.Health(version))
	if deps.Git != nil {
		// Public webhook receiver: authenticated by HMAC signature, not by user token.
		r.Post("/hooks/git/{projectID}", deps.Git.Webhook)
	}
	// Internal edge auth for git-over-HTTP (Caddy forward_auth); protected by a shared secret, never public.
	handlers.MountGitAuthInternal(r)
	// Caddy on-demand TLS gate (GET /internal/tls/ask): host-only answer, no secret; Caddy MUST block /internal/* on its public sites.
	handlers.NewTLSAskHandler(deps.DomainRepo, deps.Ingress.OwnSet(), logger).Mount(r)
	// gateway:mounts-internal begin
	// Data-plane endpoints of the gateway (/internal/gateway/*): shared secret, closed while CAPSULE_GW_SECRET is empty, never behind the user middleware.
	gwapi.MountInternal(r) // G3
	// gateway:mounts-internal end
	r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		token := os.Getenv("METRICS_TOKEN")
		if token != "" {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+token {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"metrics token required"}}`, http.StatusUnauthorized)
				return
			}
		}
		promhttp.Handler().ServeHTTP(w, r)
	})

	// ── Subdomain proxy (*.apps.tumi-ai.com → Next.js rewrite → here) ──────
	r.Handle("/_proxy/{subdomain}/*", http.HandlerFunc(proxyHandler.ProxyBySlug))
	r.Handle("/_proxy/{subdomain}", http.HandlerFunc(proxyHandler.ProxyBySlug))

	// ── Legacy path-based proxy ──────────────────────────────────────────────
	r.Handle("/apps/{orgSlug}/{projectSlug}/*", http.HandlerFunc(proxyHandler.Proxy))
	r.Handle("/apps/{orgSlug}/{projectSlug}", http.HandlerFunc(proxyHandler.Proxy))

	r.Route("/api/v1", func(r chi.Router) {
		// Public auth
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/refresh", authHandler.Refresh)
		if oidcHandler != nil {
			oidcHandler.MountAPIPublic(r)
		}
		// Run tokens of functions (customer apps introspect the capfn_ bearer) and the work node's outbound API (capnode_ token).
		// The agent API is under /api/v1 and not /internal because the node is remote and InternalEdgeGuard refuses public addresses there.
		r.Post("/fn/tokens/introspect", vpnFnHandler.Introspect)
		r.Post("/fn/agent/claim", vpnFnHandler.AgentClaim)
		r.Post("/fn/agent/sync", vpnFnHandler.AgentSync)
		r.Post("/fn/agent/runs/{runID}/finish", vpnFnHandler.AgentFinish)
		r.Post("/fn/agent/tunnels/{tunnelID}/status", vpnFnHandler.AgentTunnelStatus)
		// Relay for Lambda functions: the node offers idle connections (capnode_), the Lambda asks for one (capfn_ run token).
		r.Post("/fn/relay/node/{tunnelID}", vpnFnHandler.RelayNode)
		r.Post("/fn/relay/connect", vpnFnHandler.RelayConnect)
		r.Get("/auth/onboarding/status", authHandler.GetOnboardingStatus)
		r.Post("/auth/onboarding/verify", authHandler.VerifyOnboarding)

		// Public/Token authorized AI chat proxy
		r.Post("/ai/chat", aiHandler.Chat)
		r.Post("/ai/chat/completions", aiHandler.Chat) // OpenAI SDK compat

		// Public AI metadata — model catalog + integration skill doc (no auth)
		r.Get("/ai/models", aiHandler.ListModels)
		r.Get("/models", aiHandler.ListModels) // top-level alias
		r.Get("/ai/skill.md", aiHandler.SkillDoc)
		r.Get("/ai/skill", aiHandler.SkillDoc)

		// Protected
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(deps.AuthSvc, deps.APITokenRepo, deps.UserRepo))
			if oidcHandler != nil {
				oidcHandler.MountAPI(r)
			}

			r.Get("/auth/me", authHandler.Me)
			r.Post("/auth/logout", authHandler.Logout)

			// Platform API tokens (cap_ prefix — authenticate to Capsule REST API)
			r.Post("/user/tokens", apiTokenHandler.Create)
			r.Get("/user/tokens", apiTokenHandler.List)
			r.Delete("/user/tokens/{tokenID}", apiTokenHandler.Revoke)
			r.Patch("/user/tokens/{tokenID}", apiTokenHandler.Update)

			// Organizations
			r.Post("/orgs", orgHandler.Create)
			r.Get("/orgs", orgHandler.List)
			r.Get("/orgs/{orgID}", orgHandler.Get)
			r.Patch("/orgs/{orgID}", orgHandler.Update)
			r.Delete("/orgs/{orgID}", orgHandler.Delete)

			// Org members
			r.Get("/orgs/{orgID}/members", membersHandler.List)
			r.Post("/orgs/{orgID}/members", membersHandler.Invite)
			r.Patch("/orgs/{orgID}/members/{userID}", membersHandler.UpdateRole)
			r.Delete("/orgs/{orgID}/members/{userID}", membersHandler.Remove)

			// Projects (scoped to org)
			r.Post("/orgs/{orgID}/projects", projectHandler.Create)
			r.Get("/orgs/{orgID}/projects", projectHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}", projectHandler.Get)
			r.Patch("/orgs/{orgID}/projects/{projectID}", projectHandler.Update)
			r.Delete("/orgs/{orgID}/projects/{projectID}", projectHandler.Delete)

			// Account (org) env vars — inherited by all projects
			r.Get("/orgs/{orgID}/env", orgEnvHandler.List)
			r.Put("/orgs/{orgID}/env", orgEnvHandler.Set)
			r.Delete("/orgs/{orgID}/env/{key}", orgEnvHandler.Delete)

			// Project members (per-project roles)
			r.Get("/orgs/{orgID}/projects/{projectID}/members", projectMembersHandler.List)
			r.Put("/orgs/{orgID}/projects/{projectID}/members/{userID}", projectMembersHandler.Put)
			r.Delete("/orgs/{orgID}/projects/{projectID}/members/{userID}", projectMembersHandler.Delete)

			// Env vars (scoped to project)
			r.Get("/orgs/{orgID}/projects/{projectID}/env", envVarHandler.List)
			r.Put("/orgs/{orgID}/projects/{projectID}/env", envVarHandler.Set)
			r.Delete("/orgs/{orgID}/projects/{projectID}/env/{key}", envVarHandler.Delete)

			// Git link, auto-deploy and PR previews (scoped to project)
			if deps.Git != nil {
				r.Get("/orgs/{orgID}/projects/{projectID}/git", deps.Git.Get)
				r.Put("/orgs/{orgID}/projects/{projectID}/git", deps.Git.Put)
				r.Delete("/orgs/{orgID}/projects/{projectID}/git", deps.Git.Delete)
				r.Post("/orgs/{orgID}/projects/{projectID}/git/test", deps.Git.Test)
				r.Get("/orgs/{orgID}/projects/{projectID}/previews", deps.Git.Previews)
			}
			if deps.GitCore != nil {
				deps.GitCore.SetAuthz(az)
				r.Post("/orgs/{orgID}/projects/{projectID}/git/repo", deps.GitCore.CreateRepo)
				r.Get("/orgs/{orgID}/projects/{projectID}/git/repo", deps.GitCore.RepoStatus)
				r.Get("/orgs/{orgID}/projects/{projectID}/git/branches", deps.GitCore.Branches)
				r.Get("/orgs/{orgID}/projects/{projectID}/git/commits", deps.GitCore.Commits)
				r.Get("/orgs/{orgID}/projects/{projectID}/git/pulls", deps.GitCore.Pulls)
				r.Post("/orgs/{orgID}/projects/{projectID}/previews", deps.GitCore.CreatePreview)
				r.Delete("/orgs/{orgID}/projects/{projectID}/previews/{pr}", deps.GitCore.DeletePreview)
			}

			// git-capsule:mounts begin
			// Git Capsule route mounts, inside the authenticated /api/v1 group (variable r).
			// One line per package, alphabetical by id: `<pkg>.Mount<Pkg>(r, deps)`.
			// The gitcore Core comes from gitcore.Shared() (published by the wiring block in main.go).
			gitsync.MountGitsync(r, gitsync.Shared()) // A2: POST /git/admin/reconcile
			handlers.MountGitProtect(r, az, deps.OrgRepo, deps.ProjRepo) // A4: /git/protections (list, create, put, delete, evaluate)
			handlers.MountA5(r, handlers.A5Deps{Authz: az, Orgs: deps.OrgRepo, Audit: deps.ProjectMembers, Logger: logger}) // A5: outbound webhooks (/webhooks), notifications (/user/notifications, /user/notification-settings)
			handlers.MountEnvironments(r, az, deps.OrgRepo, deps.ProjRepo) // A6: environments, promotions, approvals (/environments, /promotions, /orgs/{orgID}/approvals)
			handlers.MountGitTokens(r) // A7:/user/git-credentials, /user/git-tokens, /user/git-ssh-keys, .../git/service-tokens
			handlers.MountAccess(r) // P4: /permissions/catalog, /me/permissions, templates, groups, assignments, access simulator and audit (docs/permissions)
			handlers.MountGitAPI(r, handlers.GitAPIDeps{Authz: az, Orgs: deps.OrgRepo, Projects: deps.ProjRepo, Git: deps.Git, Legacy: deps.GitCore, Deployments: deps.DeploymentRepo, Cache: deps.CacheStore}) // B1: repo, tree/blob/compare, branches, tags, commits, pulls, runs, CI vars/secrets, activity
			handlers.MountSecurity(r, az, deps.OrgRepo, deps.ProjRepo) // B7: /security (overview, alerts, sarif, policy, suppressions, scans, renovate)
			handlers.MountGitReview(r, handlers.GitReviewDeps{Authz: az, Orgs: deps.OrgRepo, Projects: deps.ProjRepo}) // B8: /git/codeowners, pulls/{n}/auto-merge|ready|reviewers|reviews/{id}/dismiss (pullUpdateBranch stays in B1)
			handlers.MountGitImport(r, handlers.GitImportDeps{Authz: az, Orgs: deps.OrgRepo, Projects: deps.ProjRepo}) // C1: /orgs/{o}/git/imports, projects/{p}/git/mirror (+ /sync)
			handlers.MountC2(r, handlers.C2Deps{Authz: az, Orgs: deps.OrgRepo, Logger: logger}) // C2: /orgs/{o}/audit-log (+CSV), git/activity and git/insights from git_activity (after B1: replaces its versions of those two paths)
			handlers.MountRecover(r, az, deps.OrgRepo, deps.ProjRepo) // C3: POST /git/admin/recover, GET /git/admin/recover/{runID}, POST /orgs/{o}/projects/{p}/recover
			// git-capsule:mounts end

			// gateway:mounts begin
			// Universal gateway user API (services, connection-info/token, random port, service tokens, org policy), inside the authenticated group.
			gwapi.MountAPI(r) // G3: /orgs/{o}/projects/{p}/gateway/..., /orgs/{o}/gateway/policy
			// gateway:mounts end

			// Deployments (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments/upload-url", deploymentHandler.UploadURL)
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments", deploymentHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments", deploymentHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}", deploymentHandler.Get)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}/logs", deploymentHandler.GetLogs)
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}/cancel", deploymentHandler.Cancel)
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}/rollback", deploymentHandler.Rollback)
			r.Get("/orgs/{orgID}/projects/{projectID}/connection-audit", connAuditHandler.Get)
			r.Put("/orgs/{orgID}/projects/{projectID}/connection-audit/mode", connAuditHandler.SetMode)
			r.Put("/orgs/{orgID}/projects/{projectID}/connection-audit/suppressions", connAuditHandler.PutSuppression)
			r.Delete("/orgs/{orgID}/projects/{projectID}/connection-audit/suppressions", connAuditHandler.DeleteSuppression)

			// Databases (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/databases", databaseHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/databases", databaseHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}/databases/{dbID}", databaseHandler.Get)
			r.Delete("/orgs/{orgID}/projects/{projectID}/databases/{dbID}", databaseHandler.Delete)
			r.Get("/orgs/{orgID}/databases", databaseHandler.ListByOrg)
			r.Post("/orgs/{orgID}/databases", databaseHandler.CreateOrgLevel)
			r.Get("/orgs/{orgID}/databases/{dbID}", databaseHandler.Get)
			r.Delete("/orgs/{orgID}/databases/{dbID}", databaseHandler.Delete)
			r.Post("/orgs/{orgID}/databases/{dbID}/query", databaseHandler.Query)
			r.Post("/orgs/{orgID}/projects/{projectID}/databases/{dbID}/query", databaseHandler.Query)

			// Database network access (managed host firewall rules)
			r.Get("/orgs/{orgID}/projects/{projectID}/databases/{dbID}/access", accessHandler.List)
			r.Put("/orgs/{orgID}/projects/{projectID}/databases/{dbID}/access", accessHandler.Replace)
			r.Post("/orgs/{orgID}/projects/{projectID}/databases/{dbID}/access", accessHandler.Add)
			r.Delete("/orgs/{orgID}/projects/{projectID}/databases/{dbID}/access/{ruleID}", accessHandler.Remove)

			// Extra TCP ports of a project (docker host) and who may reach them
			r.Get("/orgs/{orgID}/projects/{projectID}/ports", portsHandler.List)
			r.Put("/orgs/{orgID}/projects/{projectID}/ports", portsHandler.Replace)
			r.Post("/orgs/{orgID}/projects/{projectID}/ports/{containerPort}/access", portsHandler.AddAccess)
			r.Delete("/orgs/{orgID}/projects/{projectID}/ports/{containerPort}/access/{ruleID}", portsHandler.RemoveAccess)

			// Network: caller IP + per-project application IP allowlist
			r.Get("/network/my-ip", networkHandler.MyIP)
			r.Get("/orgs/{orgID}/projects/{projectID}/network", networkHandler.Get)
			r.Put("/orgs/{orgID}/projects/{projectID}/network", networkHandler.Put)

			// Storage Buckets (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/storage", storageHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/storage", storageHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}/storage/{dbID}", storageHandler.Get)
			r.Delete("/orgs/{orgID}/projects/{projectID}/storage/{dbID}", storageHandler.Delete)
			r.Post("/orgs/{orgID}/projects/{projectID}/storage/{dbID}/presign", storageHandler.Presign)

			// SES Email setups (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/email/setup", emailHandler.Setup)
			r.Get("/orgs/{orgID}/projects/{projectID}/email/status", emailHandler.Status)
			r.Post("/orgs/{orgID}/projects/{projectID}/email/test", emailHandler.Test)
			r.Get("/orgs/{orgID}/projects/{projectID}/email/stats", emailHandler.Stats)
			r.Get("/orgs/{orgID}/projects/{projectID}/email/dns-records", emailHandler.DNSRecords)
			r.Post("/orgs/{orgID}/projects/{projectID}/email/send", emailHandler.Send)
			r.Get("/orgs/{orgID}/projects/{projectID}/email/logs", emailHandler.Logs)
			r.Get("/orgs/{orgID}/projects/{projectID}/email/suppressions", emailHandler.Suppressions)
			r.Delete("/orgs/{orgID}/projects/{projectID}/email/suppressions/{emailAddr}", emailHandler.DeleteSuppression)

			// Domains (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/domains", domainHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/domains", domainHandler.List)
			r.Patch("/orgs/{orgID}/projects/{projectID}/storage/{dbID}", storageHandler.Update)
			r.Post("/orgs/{orgID}/projects/{projectID}/storage/{dbID}/rotate", storageHandler.Rotate)
			r.Get("/orgs/{orgID}/projects/{projectID}/storage/{dbID}/objects", storageHandler.ListObjects)
			r.Delete("/orgs/{orgID}/projects/{projectID}/storage/{dbID}/objects", storageHandler.DeleteObject)
			r.Post("/orgs/{orgID}/projects/{projectID}/storage/{dbID}/uploads", storageHandler.StartUpload)
			r.Get("/orgs/{orgID}/projects/{projectID}/storage/{dbID}/uploads/{uploadID}", storageHandler.GetUpload)
			r.Post("/orgs/{orgID}/projects/{projectID}/storage/{dbID}/uploads/{uploadID}/complete", storageHandler.CompleteUpload)
			r.Delete("/orgs/{orgID}/projects/{projectID}/storage/{dbID}/uploads/{uploadID}", storageHandler.AbortUpload)
			r.Get("/orgs/{orgID}/projects/{projectID}/storage/quota", storageHandler.GetProjectQuota)
			r.Put("/orgs/{orgID}/projects/{projectID}/storage/quota", storageHandler.PutProjectQuota)
			r.Get("/orgs/{orgID}/storage/quota", storageHandler.GetOrgQuota)
			r.Put("/orgs/{orgID}/storage/quota", storageHandler.PutOrgQuota)
			r.Post("/orgs/{orgID}/projects/{projectID}/domains/{domainID}/verify", domainHandler.Verify)
			r.Delete("/orgs/{orgID}/projects/{projectID}/domains/{domainID}", domainHandler.Delete)
			// Domains (org-level)
			r.Get("/orgs/{orgID}/domains", domainHandler.ListByOrg)
			r.Post("/orgs/{orgID}/domains", domainHandler.CreateOrgLevel)
			r.Post("/orgs/{orgID}/domains/{domainID}/verify", domainHandler.Verify)
			r.Delete("/orgs/{orgID}/domains/{domainID}", domainHandler.Delete)

			// Workers (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/workers", workerHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/workers", workerHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}/workers/{workerID}", workerHandler.Get)
			r.Delete("/orgs/{orgID}/projects/{projectID}/workers/{workerID}", workerHandler.Delete)
			r.Post("/orgs/{orgID}/projects/{projectID}/workers/{workerID}/start", workerHandler.Start)
			r.Post("/orgs/{orgID}/projects/{projectID}/workers/{workerID}/stop", workerHandler.Stop)

			// Data backups (scoped to project) and platform backups (platform admins)
			if backupsHandler != nil {
				r.Get("/orgs/{orgID}/projects/{projectID}/backups", backupsHandler.Get)
				r.Put("/orgs/{orgID}/projects/{projectID}/backups", backupsHandler.Put)
				r.Post("/orgs/{orgID}/projects/{projectID}/backups/run", backupsHandler.Run)
				r.Post("/orgs/{orgID}/projects/{projectID}/backups/verify", backupsHandler.Verify)
				r.Get("/orgs/{orgID}/projects/{projectID}/backups/snapshots", backupsHandler.Snapshots)
				r.Post("/orgs/{orgID}/projects/{projectID}/backups/restore", backupsHandler.Restore)
				r.Get("/platform/backups", backupsHandler.PlatformGet)
				r.Post("/platform/backups/run", backupsHandler.PlatformRun)
				r.Post("/platform/backups/verify", backupsHandler.PlatformVerify)
			}

			// Logs (scoped to project)
			r.Get("/orgs/{orgID}/projects/{projectID}/logs/runtime", logsHandler.GetRuntimeLogs)
			r.Get("/orgs/{orgID}/projects/{projectID}/logs/lambda", logsHandler.GetLambdaLogs)
			r.Get("/orgs/{orgID}/projects/{projectID}/logs/workers/{workerID}", logsHandler.GetWorkerLogs)
			r.Get("/orgs/{orgID}/projects/{projectID}/logs/storage", logsHandler.GetStorageLogs)
			r.Get("/orgs/{orgID}/projects/{projectID}/logs/cron", logsHandler.GetCronLogs)
			// Source discovery: returns distinct source_ids for a log type
			r.Get("/orgs/{orgID}/projects/{projectID}/logs/{source}/sources", logsHandler.GetLogSources)

			// Cron Jobs (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/crons", cronHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/crons", cronHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}/crons/{cronID}", cronHandler.Get)
			r.Delete("/orgs/{orgID}/projects/{projectID}/crons/{cronID}", cronHandler.Delete)
			r.Post("/orgs/{orgID}/projects/{projectID}/crons/{cronID}/trigger", cronHandler.Trigger)

			// VPN Connector: one tunnel per project, functions that run inside it (docs/vpn-connector.md)
			r.Post("/orgs/{orgID}/projects/{projectID}/vpn", vpnFnHandler.CreateVPN)
			r.Get("/orgs/{orgID}/projects/{projectID}/vpn", vpnFnHandler.ListVPN)
			r.Get("/orgs/{orgID}/projects/{projectID}/vpn/{name}", vpnFnHandler.GetVPN)
			r.Delete("/orgs/{orgID}/projects/{projectID}/vpn/{name}", vpnFnHandler.DeleteVPN)
			r.Put("/orgs/{orgID}/projects/{projectID}/vpn/{name}/enabled", vpnFnHandler.SetVPNEnabled)
			r.Get("/orgs/{orgID}/projects/{projectID}/vpn/{name}/events", vpnFnHandler.VPNEvents)
			r.Post("/orgs/{orgID}/projects/{projectID}/fn/functions", vpnFnHandler.DeployFn)
			r.Get("/orgs/{orgID}/projects/{projectID}/fn/functions", vpnFnHandler.ListFn)
			r.Get("/orgs/{orgID}/projects/{projectID}/fn/functions/{name}", vpnFnHandler.GetFn)
			r.Delete("/orgs/{orgID}/projects/{projectID}/fn/functions/{name}", vpnFnHandler.DeleteFn)
			r.Post("/orgs/{orgID}/projects/{projectID}/fn/functions/{name}/run", vpnFnHandler.RunFn)
			r.Post("/orgs/{orgID}/projects/{projectID}/fn/functions/{name}/enqueue", vpnFnHandler.EnqueueFn)
			r.Get("/orgs/{orgID}/projects/{projectID}/fn/functions/{name}/runs", vpnFnHandler.ListRuns)
			r.Get("/orgs/{orgID}/projects/{projectID}/fn/runs/{runID}", vpnFnHandler.GetRun)
			r.Post("/orgs/{orgID}/projects/{projectID}/fn/runs/{runID}/cancel", vpnFnHandler.CancelRun)

			// Bedrock AI Utility Keys and Helpers
			// (/ai/models is now registered publicly above)
			r.Post("/ai/keys", aiHandler.CreateKey)
			r.Get("/ai/keys", aiHandler.ListKeys)
			r.Patch("/ai/keys/{keyID}", aiHandler.UpdateKey)
			r.Delete("/ai/keys/{keyID}", aiHandler.RevokeKey)

			r.Post("/ai/dockerfile", aiHandler.Dockerfile)
			r.Post("/ai/explain-failure", aiHandler.ExplainFailure)
			r.Post("/ai/optimize-costs", aiHandler.OptimizeCosts)

			// Pricing estimate
			r.Post("/pricing/estimate", pricingHandler.Estimate)

			// Platform capabilities (any authenticated user): which optional services are on
			r.Get("/platform/capabilities", handlers.PlatformCapabilities)

			// AWS Spend and Credits tracking
			r.Get("/aws/billing", billingHandler.GetBillingSummary)

			// Admin — user management (admin role enforced per-handler)
			r.Get("/admin/users", adminHandler.ListUsers)
			r.Post("/admin/users", adminHandler.CreateUser)
			r.Patch("/admin/users/{userID}/suspend", adminHandler.SuspendUser)
			r.Patch("/admin/users/{userID}/unsuspend", adminHandler.UnsuspendUser)
			r.Patch("/admin/users/{userID}/role", adminHandler.SetUserRole)
			r.Delete("/admin/users/{userID}", adminHandler.DeleteUser)
		})
	})

	return r
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
