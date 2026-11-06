// Command aimm-dev serves the multimodal AI routes of Capsule on their own, for developing the panel and the CLI without Postgres:
// the real handlers and the real AWS services (Bedrock, Transcribe, Polly), with one organization, one project and one bucket kept in
// memory and no sign-in (any bearer token is accepted). It listens on localhost only.
//
//	AWS_PROFILE=tumi-admin AWS_REGION=us-east-1 go run ./cmd/aimm-dev -addr 127.0.0.1:8080
//
// Then point the CLI at it with --api-url and the panel with NEXT_PUBLIC_API_URL. Never deploy it: it has no authentication.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/aimm"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

type orgs struct {
	domain.OrganizationRepository
}

func (orgs) GetMemberRole(context.Context, uuid.UUID, uuid.UUID) (string, error) { return "owner", nil }
func (orgs) IsMember(context.Context, uuid.UUID, uuid.UUID) (bool, error)        { return true, nil }

type buckets struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (b *buckets) Get(_ context.Context, _ uuid.UUID, bucket, key string, max int64) ([]byte, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[bucket+"/"+key]
	if !ok {
		return nil, "", handlers.ErrBucketNotFound
	}
	if int64(len(d)) > max {
		return nil, "", handlers.ErrObjectTooLarge
	}
	return d, "application/octet-stream", nil
}
func (b *buckets) Put(_ context.Context, _ uuid.UUID, bucket, key string, d []byte, _ string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[bucket+"/"+key] = d
	return nil
}
func (b *buckets) List(_ context.Context, _ uuid.UUID, bucket, prefix string, _ int) ([]handlers.BucketObject, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []handlers.BucketObject
	for k, d := range b.data {
		if strings.HasPrefix(k, bucket+"/"+prefix) {
			out = append(out, handlers.BucketObject{Key: strings.TrimPrefix(k, bucket+"/"), Size: int64(len(d))})
		}
	}
	return out, nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (loopback only)")
	stage := flag.String("stage-bucket", os.Getenv("CAPSULE_AI_STAGE_BUCKET"), "S3 bucket for Transcribe (default capsule-artifacts-<account>)")
	budget := flag.Float64("budget", 2.0, "daily budget in USD for the project (0 = no cap)")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		log.Fatal("aimm-dev has no authentication: it only listens on loopback")
	}
	ctx := context.Background()
	c, err := awsclient.New(ctx, os.Getenv("AWS_REGION"), "", "", os.Getenv("AWS_ACCOUNT_ID"))
	if err != nil {
		log.Fatal(err)
	}
	if *stage == "" {
		*stage = "capsule-artifacts-598806201852"
	}
	kv := aimm.NewMemKV()
	bk := &buckets{data: map[string][]byte{
		"docs/factura-luz.txt":   []byte("Factura de electricidad de octubre: consumo 320 kWh, total 148 soles."),
		"docs/receta-ceviche.md": []byte("Receta de ceviche: pescado fresco, limón, ají, cebolla y cilantro."),
		"docs/contrato.txt":      []byte("Contrato de alquiler de oficina por 12 meses, renta mensual de 900 dólares."),
	}}
	h := handlers.NewAIMMHandler(handlers.AIMMDeps{
		Orgs: orgs{}, Catalog: aimm.NewCatalog(c.BedrockCtl, c.Region), Ops: &aimm.Ops{RT: c.Bedrock}, Polly: c.Polly, Bidi: c.Bedrock,
		Trans: &aimm.Transcriber{API: c.Transcribe, Stage: &aimm.S3Stage{API: c.S3, Bucket: *stage}, Jobs: kv}, Quota: &aimm.Quota{KV: kv, DailyUSD: *budget},
		Buckets: bk, Cache: devCache{kv}, Logger: slog.Default(),
	})
	org := domain.Organization{ID: uuid.MustParse("11111111-1111-1111-1111-111111111111"), Name: "Dev organization", Slug: "dev"}
	proj := domain.Project{ID: uuid.MustParse("22222222-2222-2222-2222-222222222222"), OrgID: org.ID, Name: "Dev project", Slug: "dev-project"}

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				r = r.WithContext(middleware.WithUser(r.Context(), &domain.User{ID: uuid.MustParse("33333333-3333-3333-3333-333333333333"), Email: "dev@example.com", Name: "Dev"}))
			}
			next.ServeHTTP(w, r)
		})
	})
	json := func(w http.ResponseWriter, s string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(s))
	}
	r.Get("/api/v1/orgs", func(w http.ResponseWriter, _ *http.Request) {
		json(w, fmt.Sprintf(`{"data":[{"id":%q,"name":%q,"slug":%q}]}`, org.ID, org.Name, org.Slug))
	})
	r.Get("/api/v1/orgs/{orgID}/projects", func(w http.ResponseWriter, _ *http.Request) {
		json(w, fmt.Sprintf(`{"data":[{"id":%q,"org_id":%q,"name":%q,"slug":%q}]}`, proj.ID, org.ID, proj.Name, proj.Slug))
	})
	r.Get("/api/v1/orgs/{orgID}/projects/{projectID}/storage", func(w http.ResponseWriter, _ *http.Request) {
		json(w, `{"data":[{"id":"44444444-4444-4444-4444-444444444444","name":"docs","engine":"objstore","db_name":"docs","status":"available","bucket":"docs"}]}`)
	})
	h.SetLegacyModels(func(w http.ResponseWriter, _ *http.Request) { json(w, `{"data":[]}`) })
	r.Get("/api/v1/ai/models", h.ModelsRoute)
	r.Get("/api/v1/ai/talk/ws", h.TalkWS)
	base := "/api/v1/orgs/{orgID}/projects/{projectID}/ai"
	r.Post(base+"/chat", h.Chat)
	r.Post(base+"/embeddings", h.Embeddings)
	r.Post(base+"/embeddings/search", h.SearchEmbeddings)
	r.Post(base+"/rerank", h.Rerank)
	r.Post(base+"/transcribe", h.Transcribe)
	r.Get(base+"/jobs/{jobID}", h.Job)
	r.Post(base+"/speech", h.Speech)
	r.Get(base+"/voices", h.Voices)
	r.Post(base+"/images", h.Images)
	r.Post(base+"/talk", h.Talk)
	r.Post(base+"/talk/ticket", h.TalkTicket)
	r.Get(base+"/usage", h.Usage)

	log.Printf("aimm-dev on http://%s  org %s project %s  region %s  stage bucket %s  budget $%.2f/day", *addr, org.ID, proj.ID, c.Region, *stage, *budget)
	srv := &http.Server{Addr: *addr, Handler: r, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// devCache adapts the in-memory KV to the platform cache interface.
type devCache struct{ kv *aimm.MemKV }

func (d devCache) Get(ctx context.Context, k string) (string, error) { return d.kv.Get(ctx, k) }
func (d devCache) Set(ctx context.Context, k, v string, ttl int) error {
	return d.kv.Set(ctx, k, v, ttl)
}
func (d devCache) Del(ctx context.Context, k string) error { return d.kv.Set(ctx, k, "", 1) }
