package server

import (
	"log/slog"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type Deps struct {
	AuthSvc        domain.AuthService
	OrgRepo        domain.OrganizationRepository
	ProjRepo       domain.ProjectRepository
	EnvVarRepo     domain.EnvVarRepository
	DeploymentRepo domain.DeploymentRepository
}

func newRouter(cfg *config.Config, logger *slog.Logger, version string, deps Deps) *chi.Mux {
	authHandler       := handlers.NewAuthHandler(deps.AuthSvc)
	orgHandler        := handlers.NewOrgHandler(deps.OrgRepo)
	projectHandler    := handlers.NewProjectHandler(deps.ProjRepo, deps.OrgRepo)
	envVarHandler     := handlers.NewEnvVarHandler(deps.EnvVarRepo, deps.OrgRepo, deps.ProjRepo)
	deploymentHandler := handlers.NewDeploymentHandler(deps.DeploymentRepo, deps.OrgRepo, deps.ProjRepo)

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

	r.Get("/health", handlers.Health(version))

	r.Route("/api/v1", func(r chi.Router) {
		// Public auth
		r.Post("/auth/register", authHandler.Register)
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/refresh", authHandler.Refresh)

		// Protected
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(deps.AuthSvc))

			r.Get("/auth/me", authHandler.Me)

			// Organizations
			r.Post("/orgs", orgHandler.Create)
			r.Get("/orgs", orgHandler.List)
			r.Get("/orgs/{orgID}", orgHandler.Get)
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
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments", deploymentHandler.Create)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments", deploymentHandler.List)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}", deploymentHandler.Get)
			r.Get("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}/logs", deploymentHandler.GetLogs)
			r.Post("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}/cancel", deploymentHandler.Cancel)
		})
	})

	return r
}
