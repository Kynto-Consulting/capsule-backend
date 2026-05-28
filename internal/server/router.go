package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

type Deps struct {
	AuthSvc        domain.AuthService
	OrgRepo        domain.OrganizationRepository
	ProjRepo       domain.ProjectRepository
	EnvVarRepo     domain.EnvVarRepository
	DeploymentRepo domain.DeploymentRepository
	CacheStore     domain.CacheStore // optional; may be nil

	DatabaseRepo       domain.DatabaseRepository
	DomainRepo         domain.DomainRepository
	APITokenRepo       domain.APITokenRepository
	WorkerRepo         domain.WorkerRepository
	CronJobRepo        domain.CronJobRepository
	ExecLogRepo        domain.ExecutionLogRepository
	EmailLogRepo       domain.EmailLogRepository
	AWSClients         *awsclient.Clients
	ALBDNSName         string
	DBSubnetGroup      string
	RDSSecurityGroupID string
	PublicHost         string
	SecretKey          string
	ArtifactsBucket    string
}

func newRouter(cfg *config.Config, logger *slog.Logger, version string, deps Deps) *chi.Mux {
	authHandler       := handlers.NewAuthHandler(deps.AuthSvc, deps.CacheStore)
	orgHandler        := handlers.NewOrgHandler(deps.OrgRepo)
	projectHandler    := handlers.NewProjectHandler(deps.ProjRepo, deps.OrgRepo)
	envVarHandler     := handlers.NewEnvVarHandler(deps.EnvVarRepo, deps.OrgRepo, deps.ProjRepo)
	deploymentHandler := handlers.NewDeploymentHandler(deps.DeploymentRepo, deps.OrgRepo, deps.ProjRepo, deps.AWSClients, deps.ArtifactsBucket)
	databaseHandler   := handlers.NewDatabaseHandler(
		deps.DatabaseRepo, deps.OrgRepo, deps.ProjRepo,
		deps.AWSClients, deps.SecretKey,
		deps.DBSubnetGroup, deps.RDSSecurityGroupID, deps.PublicHost, logger,
	)
	domainHandler := handlers.NewDomainHandler(
		deps.DomainRepo, deps.OrgRepo, deps.ProjRepo,
		deps.AWSClients, deps.ALBDNSName, logger,
	)
	storageHandler := handlers.NewStorageHandler(
		deps.DatabaseRepo, deps.OrgRepo, deps.ProjRepo,
		deps.AWSClients, deps.SecretKey, logger,
	)
	emailHandler := handlers.NewEmailHandler(
		deps.DatabaseRepo, deps.OrgRepo, deps.ProjRepo,
		deps.EmailLogRepo, deps.AWSClients, deps.SecretKey, logger,
	)
	aiHandler := handlers.NewAIHandler(
		deps.APITokenRepo, deps.OrgRepo, deps.ProjRepo, deps.DeploymentRepo,
		deps.AWSClients, logger, deps.AuthSvc,
	)
	pricingHandler := handlers.NewPricingHandler()
	billingHandler := handlers.NewBillingHandler(deps.DatabaseRepo, deps.AWSClients)
	proxyHandler := handlers.NewProxyHandler(deps.OrgRepo, deps.ProjRepo, deps.DomainRepo, deps.DeploymentRepo, deps.ExecLogRepo, deps.AWSClients)
	workerHandler := handlers.NewWorkerHandler(deps.WorkerRepo, deps.OrgRepo, deps.ProjRepo, logger)
	cronHandler := handlers.NewCronJobHandler(deps.CronJobRepo, deps.OrgRepo, deps.ProjRepo, deps.ExecLogRepo, logger)
	logsHandler := handlers.NewLogsHandler(deps.OrgRepo, deps.ProjRepo, deps.ExecLogRepo, logger)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(middleware.Logger(logger))
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.RateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSAllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "Idempotency-Key"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Custom domain middleware — intercept requests from non-platform hosts
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Never intercept health checks, API routes, or proxy paths
			path := r.URL.Path
			if path == "/health" ||
				strings.HasPrefix(path, "/api/") ||
				strings.HasPrefix(path, "/_proxy/") ||
				strings.HasPrefix(path, "/apps/") {
				next.ServeHTTP(w, r)
				return
			}

			host := r.Host
			// Strip port
			if i := strings.LastIndex(host, ":"); i >= 0 {
				host = host[:i]
			}
			// Only intercept non-platform hosts
			if host != "" &&
				!strings.HasSuffix(host, ".apps.tumi-ai.com") &&
				!strings.HasSuffix(host, ".tumi-ai.com") &&
				host != "localhost" {
				proxyHandler.ProxyByHost(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	r.Get("/health", handlers.Health(version))

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
		r.Get("/auth/onboarding/status", authHandler.GetOnboardingStatus)
		r.Post("/auth/onboarding/verify", authHandler.VerifyOnboarding)

		// Public/Token authorized AI chat proxy
		r.Post("/ai/chat", aiHandler.Chat)

		// Protected
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(deps.AuthSvc))

			r.Get("/auth/me", authHandler.Me)
			r.Post("/auth/logout", authHandler.Logout)

			// Organizations
			r.Post("/orgs", orgHandler.Create)
			r.Get("/orgs", orgHandler.List)
			r.Get("/orgs/{orgID}", orgHandler.Get)
			r.Patch("/orgs/{orgID}", orgHandler.Update)
			r.Delete("/orgs/{orgID}", orgHandler.Delete)

			// Projects (scoped to org)
			r.Post("/orgs/{orgID}/projects", projectHandler.Create)
			r.Get("/orgs/{orgID}/projects", projectHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}", projectHandler.Get)
			r.Patch("/orgs/{orgID}/projects/{projectID}", projectHandler.Update)
			r.Delete("/orgs/{orgID}/projects/{projectID}", projectHandler.Delete)

			// Env vars (scoped to project)
			r.Get("/orgs/{orgID}/projects/{projectID}/env", envVarHandler.List)
			r.Put("/orgs/{orgID}/projects/{projectID}/env", envVarHandler.Set)
			r.Delete("/orgs/{orgID}/projects/{projectID}/env/{key}", envVarHandler.Delete)

			// Deployments (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments/upload-url", deploymentHandler.UploadURL)
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments", deploymentHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments", deploymentHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}", deploymentHandler.Get)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}/logs", deploymentHandler.GetLogs)
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}/cancel", deploymentHandler.Cancel)

			// Databases (scoped to project)
			r.Post("/orgs/{orgID}/projects/{projectID}/databases", databaseHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/databases", databaseHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}/databases/{dbID}", databaseHandler.Get)
			r.Delete("/orgs/{orgID}/projects/{projectID}/databases/{dbID}", databaseHandler.Delete)
			r.Get("/orgs/{orgID}/databases", databaseHandler.ListByOrg)
			r.Post("/orgs/{orgID}/databases", databaseHandler.CreateOrgLevel)
			r.Get("/orgs/{orgID}/databases/{dbID}", databaseHandler.Get)
			r.Delete("/orgs/{orgID}/databases/{dbID}", databaseHandler.Delete)

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

			// Bedrock AI Utility Keys and Helpers
			r.Get("/ai/models", aiHandler.ListModels)
			r.Post("/ai/keys", aiHandler.CreateKey)
			r.Get("/ai/keys", aiHandler.ListKeys)
			r.Patch("/ai/keys/{keyID}", aiHandler.UpdateKey)
			r.Delete("/ai/keys/{keyID}", aiHandler.RevokeKey)

			r.Post("/ai/dockerfile", aiHandler.Dockerfile)
			r.Post("/ai/explain-failure", aiHandler.ExplainFailure)
			r.Post("/ai/optimize-costs", aiHandler.OptimizeCosts)

			// Pricing estimate
			r.Post("/pricing/estimate", pricingHandler.Estimate)

			// AWS Spend and Credits tracking
			r.Get("/aws/billing", billingHandler.GetBillingSummary)
		})
	})

	return r
}
