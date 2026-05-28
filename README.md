# Capsule Backend

Go REST API server powering the Capsule platform. Handles authentication, project management, deployment orchestration, database provisioning, and AWS service integration.

---

## Tech Stack

| Component       | Technology                        |
|-----------------|-----------------------------------|
| Language        | Go 1.22+                          |
| HTTP router     | [Chi v5](https://github.com/go-chi/chi) |
| Database driver | [pgx v5](https://github.com/jackc/pgx) |
| Cache           | Redis 7 via `go-redis`            |
| Auth            | JWT (access 15 min / refresh 7 days) |
| Logging         | `log/slog` (structured JSON)      |
| AWS SDK         | aws-sdk-go-v2                     |
| Linting         | golangci-lint                     |

---

## Prerequisites

- Go 1.22+
- PostgreSQL 16
- Redis 7
- AWS credentials (for AWS-backed features)

---

## Local Setup

```bash
# 1. Start infrastructure dependencies
docker compose up -d postgres redis   # from the repo root

# 2. Configure environment
cp .env.example .env
# Edit .env — at minimum set DATABASE_URL and CAPSULE_SECRET_KEY

# 3. Run database migrations
go run ./cmd/server migrate up

# 4. Start the server
go run ./cmd/server
# API available at http://localhost:8080
```

---

## Environment Variables

### Required

| Variable             | Description                                   |
|----------------------|-----------------------------------------------|
| `DATABASE_URL`       | PostgreSQL connection URL                     |
| `CAPSULE_SECRET_KEY` | JWT signing secret (long random string)       |

### Optional — Application

| Variable               | Default                    | Description                                           |
|------------------------|----------------------------|-------------------------------------------------------|
| `CAPSULE_ENV`          | `development`              | Runtime environment (`development` or `production`)   |
| `CAPSULE_PORT`         | `8080`                     | Port the HTTP server binds to                         |
| `CAPSULE_LOG_LEVEL`    | `info`                     | Log level: `debug`, `info`, `warn`, `error`           |
| `REDIS_URL`            | `redis://localhost:6379/0` | Redis connection URL                                  |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000`    | Comma-separated allowed CORS origins                  |
| `RATE_LIMIT_RPS`       | `100`                      | Sustained requests per second per IP                  |
| `RATE_LIMIT_BURST`     | `200`                      | Burst allowance for the rate limiter                  |

### Optional — AWS

| Variable               | Default      | Description                                             |
|------------------------|--------------|---------------------------------------------------------|
| `AWS_DEFAULT_REGION`   | `us-east-1`  | AWS region for all SDK calls                            |
| `AWS_ACCOUNT_ID`       | —            | AWS account ID (used to construct ECR registry URL)     |
| `ECR_REGISTRY`         | —            | ECR registry hostname for image push/pull               |
| `ARTIFACTS_BUCKET`     | —            | S3 bucket for deployment source archive uploads         |

### Optional — Infrastructure

| Variable                 | Default   | Description                                              |
|--------------------------|-----------|----------------------------------------------------------|
| `ALB_DNS_NAME`           | —         | ALB DNS name; used when creating custom domain targets   |
| `DB_SUBNET_GROUP`        | `capsule` | RDS DB subnet group name for database provisioning       |
| `RDS_SECURITY_GROUP_ID`  | —         | Security group ID attached to provisioned RDS instances  |
| `CAPSULE_PUBLIC_HOST`    | —         | Public hostname or IP of this server (displayed to users)|
| `CAPSULE_APPS_DOMAIN`    | —         | Base domain for platform-assigned app subdomains         |
| `CAPSULE_STATIC_BUCKET`  | —         | S3 bucket used for static asset hosting                  |

---

## Project Structure

```
backend/
├── cmd/
│   └── server/          Entry point (main.go, migrations subcommand)
├── internal/
│   ├── config/          Environment variable loading and validation
│   ├── domain/          Domain models and service/repository interfaces
│   ├── repository/      PostgreSQL implementations (pgx)
│   │   └── migrations/  SQL migration files
│   ├── service/         Business logic layer
│   └── server/
│       ├── handlers/    HTTP request handlers (one file per resource)
│       ├── middleware/   Auth, logging, rate limiting, recovery, timeout
│       └── router.go    Route registration
└── pkg/
    └── awsclient/       AWS SDK client initialization and helpers
```

### Request Flow

```
HTTP Request
    │
    ▼
Middleware chain
(RequestID → RealIP → Logger → Recovery → Timeout → RateLimiter → CORS → CustomDomain)
    │
    ▼
Handler (server/handlers/)
    │
    ▼
Service (internal/service/)
    │
    ▼
Repository (internal/repository/)
    │
    ▼
PostgreSQL / Redis / AWS
```

---

## API Routes

All authenticated routes require a `Bearer` token in the `Authorization` header.

| Method   | Path                                                             | Description                        | Auth |
|----------|------------------------------------------------------------------|------------------------------------|------|
| `GET`    | `/health`                                                        | Health check                       | No   |
| `POST`   | `/api/v1/auth/register`                                         | Register new account               | No   |
| `POST`   | `/api/v1/auth/login`                                            | Login                              | No   |
| `POST`   | `/api/v1/auth/refresh`                                          | Refresh access token               | No   |
| `GET`    | `/api/v1/auth/me`                                               | Get current user                   | Yes  |
| `POST`   | `/api/v1/auth/logout`                                           | Logout                             | Yes  |
| `POST`   | `/api/v1/ai/chat`                                               | AI chat (token or JWT)             | No   |
| `POST/GET` | `/api/v1/orgs`                                                | Create / list organizations        | Yes  |
| `GET/PATCH/DELETE` | `/api/v1/orgs/{orgID}`                                | Get / update / delete org          | Yes  |
| `POST/GET` | `/api/v1/orgs/{orgID}/projects`                               | Create / list projects             | Yes  |
| `GET/PATCH/DELETE` | `/api/v1/orgs/{orgID}/projects/{projectID}`           | Get / update / delete project      | Yes  |
| `GET/PUT` | `/api/v1/orgs/{orgID}/projects/{projectID}/env`               | List / set environment variables   | Yes  |
| `POST/GET` | `/api/v1/orgs/{orgID}/projects/{projectID}/deployments`      | Create / list deployments          | Yes  |
| `GET`    | `/api/v1/orgs/{orgID}/projects/{projectID}/deployments/{id}/logs` | Stream deployment logs          | Yes  |
| `POST/GET` | `/api/v1/orgs/{orgID}/projects/{projectID}/databases`        | Provision / list databases         | Yes  |
| `POST/GET` | `/api/v1/orgs/{orgID}/projects/{projectID}/storage`          | Create / list S3 buckets           | Yes  |
| `POST/GET` | `/api/v1/orgs/{orgID}/projects/{projectID}/email/setup`      | Configure SES email                | Yes  |
| `POST/GET` | `/api/v1/orgs/{orgID}/projects/{projectID}/domains`          | Add / list custom domains          | Yes  |
| `POST/GET` | `/api/v1/orgs/{orgID}/projects/{projectID}/workers`          | Create / list workers              | Yes  |
| `POST/GET` | `/api/v1/orgs/{orgID}/projects/{projectID}/crons`            | Create / list cron jobs            | Yes  |
| `POST`   | `/api/v1/ai/keys`                                               | Create Bedrock API key             | Yes  |
| `POST`   | `/api/v1/ai/dockerfile`                                         | Generate Dockerfile via AI         | Yes  |
| `POST`   | `/api/v1/pricing/estimate`                                      | Estimate resource cost             | Yes  |
| `GET`    | `/api/v1/aws/billing`                                           | AWS spend summary                  | Yes  |

---

## Adding a New Feature

1. **Define the domain model** in `internal/domain/` — struct and interface(s)
2. **Implement the repository** in `internal/repository/` backed by pgx
3. **Implement the service** in `internal/service/` with business logic
4. **Write the handler** in `internal/server/handlers/`
5. **Register the route** in `internal/server/router.go`

Follow the constructor injection pattern used by all existing handlers:

```go
func NewThingHandler(repo domain.ThingRepository, orgRepo domain.OrganizationRepository) *ThingHandler {
    return &ThingHandler{repo: repo, orgRepo: orgRepo}
}
```

---

## Running Tests

```bash
# Unit tests
go test ./...

# With race detector and coverage
go test -race -coverprofile=coverage.out ./...

# Integration tests (requires running PostgreSQL and Redis)
go test -tags=integration -race -v ./...

# Lint
golangci-lint run --timeout=5m ./...
```

---

## Key Packages

| Package                         | Purpose                                                    |
|---------------------------------|------------------------------------------------------------|
| `internal/domain`               | Domain models, service interfaces, repository interfaces   |
| `internal/repository`           | pgx-backed PostgreSQL implementations                      |
| `internal/service`              | Business logic; coordinates repos and AWS clients          |
| `internal/server/handlers`      | HTTP handlers; thin layer over services                    |
| `internal/server/middleware`    | Auth (JWT), rate limiting, logging, recovery, timeout      |
| `internal/config`               | Environment variable loading with validation               |
| `pkg/awsclient`                 | Shared AWS SDK client initialization (EC2, ECR, RDS, S3, SES, Bedrock, ALB) |
