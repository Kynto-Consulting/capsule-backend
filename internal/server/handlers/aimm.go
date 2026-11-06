package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime/multipart"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/aimm"
	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitaudit"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// AIMMHandler serves the multimodal AI surface of a project: /orgs/{orgID}/projects/{projectID}/ai/... (docs/AI_MULTIMODAL.md).
// Who may use what is decided with the permission atoms that already exist (see capabilityAtom); every call is audited without its content.
type AIMMHandler struct {
	authzHolder
	orgs         domain.OrganizationRepository
	cat          *aimm.Catalog
	ops          *aimm.Ops
	tr           *aimm.Transcriber // nil when no staging bucket is configured
	polly        aimm.PollyAPI
	bidi         aimm.BidiRuntime
	quota        *aimm.Quota
	buckets      BucketIO // nil when the own object store is off
	cache        domain.CacheStore
	logger       *slog.Logger
	legacyModels http.HandlerFunc
}

// AIMMDeps wires the handler.
type AIMMDeps struct {
	Orgs    domain.OrganizationRepository
	Catalog *aimm.Catalog
	Ops     *aimm.Ops
	Trans   *aimm.Transcriber
	Polly   aimm.PollyAPI
	Bidi    aimm.BidiRuntime
	Quota   *aimm.Quota
	Buckets BucketIO
	Cache   domain.CacheStore
	Logger  *slog.Logger
}

// NewAIMMHandler builds the handler.
func NewAIMMHandler(d AIMMDeps) *AIMMHandler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &AIMMHandler{orgs: d.Orgs, cat: d.Catalog, ops: d.Ops, tr: d.Trans, polly: d.Polly, bidi: d.Bidi, quota: d.Quota, buckets: d.Buckets, cache: d.Cache, logger: d.Logger}
}

// capabilityAtom is the permission atom each capability needs on the project. The catalog of atoms is append-only and versioned by the
// permission SPEC, so AI reuses the closest existing ones: reading-type uses (models, embeddings, rerank, chat) need project:read;
// the uses that produce files (speech, transcription, images, speech to speech) need storage:presign, the atom of whoever may write
// into the project's buckets. Dedicated ai:* atoms are proposed in docs/AI_MULTIMODAL.md for the next catalog version.
func capabilityAtom(c aimm.Capability) string {
	switch c {
	case aimm.CapSTT, aimm.CapTTS, aimm.CapSpeechToSpeech, aimm.CapImageGenerate, aimm.CapImageEdit:
		return "storage:presign"
	}
	return "project:read"
}

// ---- errors ----

func (h *AIMMHandler) fail(w http.ResponseWriter, err error) {
	var qe *aimm.QuotaError
	switch {
	case errors.As(err, &qe):
		respondErrorDetails(w, http.StatusTooManyRequests, "QUOTA_EXCEEDED", qe.Error(), map[string]any{"used_usd": qe.UsedUSD, "limit_usd": qe.LimitUSD, "needed_usd": qe.NeededUSD})
	case errors.Is(err, aimm.ErrBadInput):
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", strings.TrimPrefix(err.Error(), aimm.ErrBadInput.Error()+": "))
	case errors.Is(err, aimm.ErrNoAccess):
		respondError(w, http.StatusForbidden, "MODEL_ACCESS", err.Error()+" — an AWS administrator must enable the model (Bedrock > Model access) or grant the backend role bedrock:InvokeModel")
	case errors.Is(err, aimm.ErrUnsupported):
		respondError(w, http.StatusUnprocessableEntity, "UNSUPPORTED", err.Error())
	case errors.Is(err, ErrBucketNotFound):
		respondError(w, http.StatusNotFound, "BUCKET_NOT_FOUND", err.Error())
	case errors.Is(err, ErrObjectTooLarge):
		respondError(w, http.StatusRequestEntityTooLarge, "TOO_LARGE", err.Error())
	case errors.Is(err, aimm.ErrJobNotFound):
		respondError(w, http.StatusNotFound, "NOT_FOUND", "job not found or expired")
	case errors.Is(err, context.DeadlineExceeded):
		respondError(w, http.StatusGatewayTimeout, "TIMEOUT", "the model did not answer in time")
	default:
		h.logger.Error("ai call failed", "err", err.Error())
		respondError(w, http.StatusBadGateway, "UPSTREAM_ERROR", "the AI provider failed: "+truncate(err.Error(), 300))
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---- request context ----

type aiCall struct {
	user      *domain.User
	orgID     uuid.UUID
	projectID uuid.UUID
	cap       aimm.Capability
	started   time.Time
	r         *http.Request
}

func (c *aiCall) scope() string { return "project:" + c.projectID.String() }

// begin parses ids and authorizes the capability; it answers the error itself.
func (h *AIMMHandler) begin(w http.ResponseWriter, r *http.Request, cap aimm.Capability) (*aiCall, bool) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return nil, false
	}
	projectID, ok := h.authorizeRoute(w, r, h.orgs, orgID, authz.Action(capabilityAtom(cap)))
	if !ok {
		return nil, false
	}
	if h.ops == nil || h.ops.RT == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "AI is not configured on this platform (no AWS credentials)")
		return nil, false
	}
	return &aiCall{user: middleware.GetUser(r.Context()), orgID: orgID, projectID: projectID, cap: cap, started: time.Now(), r: r}, true
}

// pickModel resolves the requested model or a default of the capability, and refuses unavailable ones with their reason.
func (h *AIMMHandler) pickModel(w http.ResponseWriter, r *http.Request, cap aimm.Capability, id string, defaults ...string) (aimm.Model, bool) {
	ctx := r.Context()
	if id == "" {
		for _, d := range defaults {
			if m, ok := h.cat.Get(ctx, d); ok && m.Available && m.Has(cap) {
				return m, true
			}
		}
		if ms := h.cat.ByCapability(ctx, cap, true); len(ms) > 0 {
			return ms[0], true
		}
		reason := ""
		for _, ci := range h.cat.Capabilities(ctx) {
			if ci.ID == cap {
				reason = ci.Reason
			}
		}
		respondErrorDetails(w, http.StatusConflict, "NO_MODEL", "no model is available for "+string(cap)+": "+reason, map[string]any{"capability": cap})
		return aimm.Model{}, false
	}
	m, ok := h.cat.Get(ctx, id)
	if !ok {
		respondError(w, http.StatusNotFound, "MODEL_NOT_FOUND", "unknown model "+id+" (GET /ai/models?capability="+string(cap)+" lists them)")
		return m, false
	}
	if !m.Has(cap) {
		respondError(w, http.StatusUnprocessableEntity, "UNSUPPORTED", fmt.Sprintf("model %s does not do %s", m.ID, cap))
		return m, false
	}
	if !m.Available {
		respondErrorDetails(w, http.StatusConflict, "MODEL_UNAVAILABLE", fmt.Sprintf("model %s is not available: %s", m.ID, m.Reason), map[string]any{"model": m.ID, "reason": m.Reason})
		return m, false
	}
	return m, true
}

// budget checks the daily quota against an estimate.
func (h *AIMMHandler) budget(w http.ResponseWriter, c *aiCall, estimate float64) bool {
	if err := h.quota.Check(c.r.Context(), c.scope(), estimate); err != nil {
		h.fail(w, err)
		return false
	}
	return true
}

// done records the spend and the audit entry. It never stores content: only model, capability, sizes and cost.
func (h *AIMMHandler) done(c *aiCall, m aimm.Model, bytesIn, bytesOut int, costUSD float64, status string, extra map[string]any) {
	ctx := context.WithoutCancel(c.r.Context())
	if status == "ok" {
		h.quota.Add(ctx, c.scope(), costUSD)
	}
	meta := map[string]any{"capability": string(c.cap), "model": m.ID, "bytes_in": bytesIn, "bytes_out": bytesOut,
		"cost_estimate_usd": costUSD, "status": status, "duration_ms": time.Since(c.started).Milliseconds()}
	for k, v := range extra {
		meta[k] = v
	}
	h.logger.Info("ai call", "capability", string(c.cap), "model", m.ID, "project", c.projectID.String(), "bytes_in", bytesIn, "bytes_out", bytesOut, "cost_usd", costUSD, "status", status)
	c2Mu.RLock()
	rec := c2Svc.recorder
	c2Mu.RUnlock()
	if rec == nil {
		return
	}
	in := gitaudit.Input{OrgID: c.orgID, ProjectID: c.projectID, Action: "ai." + strings.ReplaceAll(string(c.cap), "-", "_"), ResourceType: "ai_call",
		IP: middleware.ClientIP(c.r), UserAgent: c.r.UserAgent(), Meta: meta}
	if c.user != nil {
		in.UserID = c.user.ID
	}
	if err := rec.Record(ctx, in); err != nil {
		h.logger.Warn("ai audit entry not written", "err", err.Error())
	}
}

// ---- form parsing: multipart or JSON ----

type aFile struct {
	Name, ContentType string
	Data              []byte
}

type aForm struct {
	vals  map[string]string
	multi map[string][]string
	files map[string][]aFile
	obj   map[string]any
}

func (f *aForm) str(k string) string { return strings.TrimSpace(f.vals[k]) }
func (f *aForm) num(k string, def int) int {
	if v, err := strconv.Atoi(f.str(k)); err == nil {
		return v
	}
	return def
}
func (f *aForm) flag(k string) bool {
	v := strings.ToLower(f.str(k))
	return v == "true" || v == "1" || v == "yes"
}
func (f *aForm) list(k string) []string { return f.multi[k] }

// parseForm reads multipart/form-data (files in memory, capped by limit) or a JSON object (scalars, arrays, and <name>_base64 for files).
func (h *AIMMHandler) parseForm(w http.ResponseWriter, r *http.Request, limit int64) (*aForm, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	f := &aForm{vals: map[string]string{}, multi: map[string][]string{}, files: map[string][]aFile{}}
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "multipart/form-data"):
		mr, err := r.MultipartReader()
		if err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid multipart body")
			return nil, false
		}
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				respondTooLarge(w, err)
				return nil, false
			}
			if err := readPart(f, p); err != nil {
				respondTooLarge(w, err)
				return nil, false
			}
		}
	default:
		var obj map[string]any
		if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				respondError(w, http.StatusRequestEntityTooLarge, "TOO_LARGE", fmt.Sprintf("the request is larger than %d MB", limit>>20))
				return nil, false
			}
			respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
			return nil, false
		}
		f.obj = obj
		for k, v := range obj {
			switch x := v.(type) {
			case string:
				f.vals[k] = x
				f.multi[k] = []string{x}
			case float64:
				f.vals[k] = strconv.FormatFloat(x, 'f', -1, 64)
			case bool:
				f.vals[k] = strconv.FormatBool(x)
			case []any:
				for _, e := range x {
					if s, ok := e.(string); ok {
						f.multi[k] = append(f.multi[k], s)
					}
				}
			}
		}
	}
	return f, true
}

func respondTooLarge(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		respondError(w, http.StatusRequestEntityTooLarge, "TOO_LARGE", fmt.Sprintf("the request is larger than %d MB", mbe.Limit>>20))
		return
	}
	respondError(w, http.StatusBadRequest, "INVALID_BODY", "could not read the request body")
}

func readPart(f *aForm, p *multipart.Part) error {
	defer p.Close()
	b, err := io.ReadAll(p)
	if err != nil {
		return err
	}
	if p.FileName() != "" {
		f.files[p.FormName()] = append(f.files[p.FormName()], aFile{Name: p.FileName(), ContentType: p.Header.Get("Content-Type"), Data: b})
		return nil
	}
	f.vals[p.FormName()] = string(b)
	f.multi[p.FormName()] = append(f.multi[p.FormName()], string(b))
	return nil
}

// splitRef parses "bucket/key".
func splitRef(s string) (bucket, key string, ok bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "s3://"), "/")
	i := strings.Index(s, "/")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// files returns every file of a field: uploaded parts, <name>_base64 values, and <name>_source references ("bucket/key") read from the own store.
func (h *AIMMHandler) files(ctx context.Context, c *aiCall, f *aForm, name string, max int64) ([]aFile, error) {
	out := append([]aFile(nil), f.files[name]...)
	for _, s := range f.multi[name+"_base64"] {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, aimm.BadInput("%s_base64 is not valid base64", name)
		}
		out = append(out, aFile{Name: name, Data: b})
	}
	for _, ref := range f.multi[name+"_source"] {
		bucket, key, ok := splitRef(ref)
		if !ok {
			return nil, aimm.BadInput("%s_source must look like bucket/key", name)
		}
		if h.buckets == nil {
			return nil, aimm.BadInput("buckets are not enabled on this platform")
		}
		b, ct, err := h.buckets.Get(ctx, c.projectID, bucket, key, max)
		if err != nil {
			return nil, err
		}
		out = append(out, aFile{Name: path.Base(key), ContentType: ct, Data: b})
	}
	for _, x := range out {
		if int64(len(x.Data)) > max {
			return nil, ErrObjectTooLarge
		}
	}
	return out, nil
}

func (h *AIMMHandler) file(ctx context.Context, c *aiCall, f *aForm, name string, max int64) (*aFile, error) {
	fs, err := h.files(ctx, c, f, name, max)
	if err != nil || len(fs) == 0 {
		return nil, err
	}
	return &fs[0], nil
}

// save stores data under save_to ("bucket/key"); a trailing slash makes it a prefix and name the object name.
func (h *AIMMHandler) save(ctx context.Context, c *aiCall, target, name string, data []byte, ct string) (string, error) {
	bucket, key, ok := splitRef(target)
	if !ok {
		bucket, key, ok = splitRef(target + "/x")
		if !ok {
			return "", aimm.BadInput("save_to must look like bucket/key")
		}
		key = ""
	}
	if key == "" || strings.HasSuffix(key, "/") {
		key += name
	}
	if h.buckets == nil {
		return "", aimm.BadInput("buckets are not enabled on this platform")
	}
	if err := h.buckets.Put(ctx, c.projectID, bucket, key, data, ct); err != nil {
		return "", err
	}
	return bucket + "/" + key, nil
}

func aiExtOf(f aFile, def string) string {
	e := strings.ToLower(strings.TrimPrefix(path.Ext(f.Name), "."))
	if e == "" {
		e = strings.TrimPrefix(f.ContentType, "image/")
		e = strings.TrimPrefix(e, "video/")
	}
	if e == "jpg" {
		e = "jpeg"
	}
	if e == "" {
		return def
	}
	return e
}

// ---- catalog ----

// Models answers GET /ai/models when called with ?capability= (or ?catalog=1): the live catalog grouped by capability. Without them the
// legacy list stays as it was.
func (h *AIMMHandler) Models(w http.ResponseWriter, r *http.Request) {
	cp := aimm.Capability(r.URL.Query().Get("capability"))
	if cp != "" && !cp.Valid() {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "unknown capability; one of "+capList())
		return
	}
	only := r.URL.Query().Get("available") == "true"
	ms := h.cat.ByCapability(r.Context(), cp, only)
	if ms == nil {
		ms = []aimm.Model{}
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": ms, "capabilities": h.cat.Capabilities(r.Context()), "live": h.cat.Live(), "region": "us-east-1"})
}

func capList() string {
	var s []string
	for _, c := range aimm.AllCapabilities {
		s = append(s, string(c))
	}
	return strings.Join(s, ", ")
}

// Usage answers GET .../ai/usage: today's estimated spend of the project against its cap.
func (h *AIMMHandler) Usage(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapChat)
	if !ok {
		return
	}
	used, limit := h.quota.Usage(r.Context(), c.scope())
	respondJSON(w, http.StatusOK, map[string]any{"used_usd": used, "limit_usd": limit, "unlimited": limit <= 0, "day": time.Now().UTC().Format("2006-01-02")})
}

// ---- embeddings ----

type embedInputs struct {
	items []aimm.EmbedInput
}

func (h *AIMMHandler) embedInputs(ctx context.Context, c *aiCall, f *aForm) (*embedInputs, error) {
	var in embedInputs
	for _, t := range f.list("input") {
		in.items = append(in.items, aimm.EmbedInput{Text: t})
	}
	for _, t := range f.list("text") {
		in.items = append(in.items, aimm.EmbedInput{Text: t})
	}
	imgs, err := h.files(ctx, c, f, "image", 10<<20)
	if err != nil {
		return nil, err
	}
	for _, im := range imgs {
		in.items = append(in.items, aimm.EmbedInput{Image: im.Data, ImageFormat: aiExtOf(im, "png")})
	}
	return &in, nil
}

// Embeddings answers POST .../ai/embeddings {model?, input: string|[string], dimensions?, purpose?: document|query}; images go as files.
func (h *AIMMHandler) Embeddings(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapEmbed)
	if !ok {
		return
	}
	f, ok := h.parseForm(w, r, 40<<20)
	if !ok {
		return
	}
	m, ok := h.pickModel(w, r, aimm.CapEmbed, f.str("model"), "titan-embed-v2", "nova-embed")
	if !ok {
		return
	}
	in, err := h.embedInputs(r.Context(), c, f)
	if err != nil {
		h.fail(w, err)
		return
	}
	chars := 0
	for _, it := range in.items {
		chars += len(it.Text)
	}
	est := aimm.EstimateTokens(m, chars/4+1, 0)
	if !h.budget(w, c, est) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := h.ops.Embed(ctx, m, in.items, f.num("dimensions", 0), f.str("purpose"))
	if err != nil {
		h.done(c, m, chars, 0, 0, "error", nil)
		h.fail(w, err)
		return
	}
	cost := aimm.EstimateTokens(m, res.Tokens, 0)
	h.done(c, m, chars, len(res.Vectors)*res.Dim*4, cost, "ok", map[string]any{"inputs": len(in.items)})
	respondJSON(w, http.StatusOK, map[string]any{"model": m.ID, "dimensions": res.Dim, "vectors": res.Vectors, "usage": map[string]any{"tokens": res.Tokens}, "cost_estimate_usd": cost})
}

// SearchEmbeddings answers POST .../ai/embeddings/search {query, bucket, prefix?, top_k?, model?}: it embeds the text objects of a bucket
// (vectors are cached by content) and returns the most similar to the query.
func (h *AIMMHandler) SearchEmbeddings(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapEmbed)
	if !ok {
		return
	}
	f, ok := h.parseForm(w, r, 1<<20)
	if !ok {
		return
	}
	query, bucket := f.str("query"), f.str("bucket")
	if query == "" || bucket == "" {
		h.fail(w, aimm.BadInput("query and bucket are required"))
		return
	}
	if h.buckets == nil {
		h.fail(w, aimm.BadInput("buckets are not enabled on this platform"))
		return
	}
	m, ok := h.pickModel(w, r, aimm.CapEmbed, f.str("model"), "titan-embed-v2", "nova-embed")
	if !ok {
		return
	}
	topK := f.num("top_k", 5)
	if topK < 1 || topK > 50 {
		topK = 5
	}
	const maxDocs, maxDocBytes = 100, 32 << 10
	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	objs, err := h.buckets.List(ctx, c.projectID, bucket, f.str("prefix"), 1000)
	if err != nil {
		h.fail(w, err)
		return
	}
	type doc struct {
		key, text string
		vec       []float32
	}
	var docs []*doc
	skipped := 0
	for _, o := range objs {
		if len(docs) >= maxDocs {
			skipped++
			continue
		}
		if o.Size == 0 || o.Size > maxDocBytes || !textKey(o.Key) {
			skipped++
			continue
		}
		b, _, err := h.buckets.Get(ctx, c.projectID, bucket, o.Key, maxDocBytes)
		if err != nil {
			continue
		}
		docs = append(docs, &doc{key: o.Key, text: string(b)})
	}
	if len(docs) == 0 {
		h.fail(w, aimm.BadInput("the bucket has no text objects (txt, md, json, csv, html, log, yaml up to 32 KB) under that prefix"))
		return
	}
	// vectors already known
	var todo []int
	for i, d := range docs {
		if v := h.cachedVector(ctx, m.ID, d.text); v != nil {
			d.vec = v
		} else {
			todo = append(todo, i)
		}
	}
	chars := len(query)
	for _, i := range todo {
		chars += len(docs[i].text)
	}
	if !h.budget(w, c, aimm.EstimateTokens(m, chars/4+1, 0)) {
		return
	}
	tokens := 0
	embed := func(items []aimm.EmbedInput, purpose string) ([][]float32, error) {
		res, err := h.ops.Embed(ctx, m, items, 256, purpose)
		if err != nil {
			return nil, err
		}
		tokens += res.Tokens
		return res.Vectors, nil
	}
	for len(todo) > 0 {
		n := len(todo)
		if n > 24 {
			n = 24
		}
		var items []aimm.EmbedInput
		for _, i := range todo[:n] {
			items = append(items, aimm.EmbedInput{Text: docs[i].text})
		}
		vs, err := embed(items, "document")
		if err != nil {
			h.done(c, m, chars, 0, 0, "error", nil)
			h.fail(w, err)
			return
		}
		for j, i := range todo[:n] {
			docs[i].vec = vs[j]
			h.storeVector(ctx, m.ID, docs[i].text, vs[j])
		}
		todo = todo[n:]
	}
	qv, err := embed([]aimm.EmbedInput{{Text: query}}, "query")
	if err != nil {
		h.done(c, m, chars, 0, 0, "error", nil)
		h.fail(w, err)
		return
	}
	type hit struct {
		Key     string  `json:"key"`
		Score   float64 `json:"score"`
		Snippet string  `json:"snippet"`
	}
	hits := make([]hit, 0, len(docs))
	for _, d := range docs {
		hits = append(hits, hit{Key: d.key, Score: cosine(qv[0], d.vec), Snippet: snippet(d.text, 200)})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > topK {
		hits = hits[:topK]
	}
	cost := aimm.EstimateTokens(m, tokens, 0)
	h.done(c, m, chars, 0, cost, "ok", map[string]any{"documents": len(docs), "skipped": skipped})
	respondJSON(w, http.StatusOK, map[string]any{"model": m.ID, "bucket": bucket, "documents": len(docs), "skipped": skipped, "hits": hits, "usage": map[string]any{"tokens": tokens}, "cost_estimate_usd": cost})
}

func textKey(k string) bool {
	switch strings.ToLower(strings.TrimPrefix(path.Ext(k), ".")) {
	case "txt", "md", "markdown", "json", "csv", "html", "htm", "log", "yaml", "yml", "xml", "rst", "":
		return true
	}
	return false
}

func snippet(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func cosine(a, b []float32) float64 {
	var dot, na, nb float64
	for i := 0; i < len(a) && i < len(b); i++ {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func vecKey(model, text string) string {
	s := sha256.Sum256([]byte(text))
	return "ai:vec:" + model + ":" + hex.EncodeToString(s[:16])
}

func (h *AIMMHandler) cachedVector(ctx context.Context, model, text string) []float32 {
	if h.cache == nil {
		return nil
	}
	s, err := h.cache.Get(ctx, vecKey(model, text))
	if err != nil || s == "" {
		return nil
	}
	var v []float32
	if json.Unmarshal([]byte(s), &v) != nil {
		return nil
	}
	return v
}

func (h *AIMMHandler) storeVector(ctx context.Context, model, text string, v []float32) {
	if h.cache == nil {
		return
	}
	if b, err := json.Marshal(v); err == nil {
		_ = h.cache.Set(ctx, vecKey(model, text), string(b), 7*24*3600)
	}
}

// ---- rerank ----

// Rerank answers POST .../ai/rerank {model?, query, documents: [string], top_n?}.
func (h *AIMMHandler) Rerank(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapRerank)
	if !ok {
		return
	}
	f, ok := h.parseForm(w, r, 8<<20)
	if !ok {
		return
	}
	m, ok := h.pickModel(w, r, aimm.CapRerank, f.str("model"), "cohere-rerank-3-5")
	if !ok {
		return
	}
	docs := f.list("documents")
	est := aimm.EstimateRerank(m, len(docs))
	if !h.budget(w, c, est) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	hits, err := h.ops.Rerank(ctx, m, f.str("query"), docs, f.num("top_n", 0))
	if err != nil {
		h.done(c, m, len(f.str("query")), 0, 0, "error", nil)
		h.fail(w, err)
		return
	}
	type outHit struct {
		Index    int     `json:"index"`
		Score    float64 `json:"score"`
		Document string  `json:"document"`
	}
	out := make([]outHit, 0, len(hits))
	for _, x := range hits {
		out = append(out, outHit{x.Index, x.Score, docs[x.Index]})
	}
	h.done(c, m, len(f.str("query")), 0, est, "ok", map[string]any{"documents": len(docs)})
	respondJSON(w, http.StatusOK, map[string]any{"model": m.ID, "results": out, "cost_estimate_usd": est})
}

// ---- chat with attachments ----

// Chat answers POST .../ai/chat (multipart or JSON): prompt, model?, system?, max_tokens?, stream?, and the files image, video, document and
// audio (audio is transcribed first, because no Bedrock chat model takes audio today, and the transcript joins the prompt).
// With stream=true the answer is Server-Sent Events: data: {"delta": "..."} ... data: {"done": true, "usage": ..., "cost_estimate_usd": ...}.
func (h *AIMMHandler) Chat(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapChat)
	if !ok {
		return
	}
	f, ok := h.parseForm(w, r, 60<<20)
	if !ok {
		return
	}
	prompt := f.str("prompt")
	if prompt == "" {
		h.fail(w, aimm.BadInput("prompt is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	var atts []aimm.Attachment
	for _, spec := range []struct {
		field, kind string
		max         int64
	}{{"image", "image", 8 << 20}, {"video", "video", 40 << 20}, {"document", "document", 8 << 20}} {
		fs, err := h.files(ctx, c, f, spec.field, spec.max)
		if err != nil {
			h.fail(w, err)
			return
		}
		for _, x := range fs {
			atts = append(atts, aimm.Attachment{Kind: spec.kind, Format: aiExtOf(x, ""), Name: x.Name, Data: x.Data})
		}
	}
	hasImage, hasVideo := false, false
	for _, a := range atts {
		hasImage = hasImage || a.Kind == "image"
		hasVideo = hasVideo || a.Kind == "video"
	}
	need := aimm.CapChat
	switch {
	case hasVideo:
		need = aimm.CapVideo
	case hasImage:
		need = aimm.CapVision
	}
	m, ok := h.pickModel(w, r, need, f.str("model"), "nova-2-lite", "nova-pro", "claude-sonnet-4.5")
	if !ok {
		return
	}
	audio, err := h.files(ctx, c, f, "audio", aimm.MaxAudioBytes)
	if err != nil {
		h.fail(w, err)
		return
	}
	extraCost := 0.0
	for _, a := range audio {
		if h.tr == nil {
			h.fail(w, aimm.BadInput("audio attachments need the transcription service, which is not configured"))
			return
		}
		fm := aimm.AudioFormat(a.Name)
		if fm == "" {
			fm = aimm.AudioFormat(a.ContentType)
		}
		est := float64(len(a.Data)) / 16000 / 60
		extraCost += est * 0.024
		if !h.budget(w, c, extraCost) {
			return
		}
		tr, err := h.transcribeNow(ctx, c, a.Data, fm, f.str("lang"), est)
		if err != nil {
			h.fail(w, err)
			return
		}
		prompt = "[Transcript of the audio the user attached]\n" + tr + "\n\n" + prompt
	}
	maxTokens := f.num("max_tokens", 1024)
	if maxTokens < 1 || maxTokens > 8192 {
		maxTokens = 1024
	}
	size := len(prompt)
	for _, a := range atts {
		size += len(a.Data)
	}
	if !h.budget(w, c, aimm.EstimateTokens(m, size/4+1, maxTokens)+extraCost) {
		return
	}
	system := f.str("system")
	if f.flag("stream") {
		flusher, ok := w.(http.Flusher)
		if !ok {
			h.fail(w, errors.New("streaming is not supported by this connection"))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		send := func(v any) {
			b, _ := json.Marshal(v)
			_, _ = w.Write([]byte("data: " + string(b) + "\n\n"))
			flusher.Flush()
		}
		res, err := h.ops.AnalyzeStream(ctx, m, system, prompt, atts, maxTokens, func(d string) { send(map[string]string{"delta": d}) })
		if err != nil {
			h.done(c, m, size, 0, 0, "error", nil)
			send(map[string]any{"error": err.Error()})
			return
		}
		cost := aimm.EstimateTokens(m, res.InTokens, res.OutTokens) + extraCost
		h.done(c, m, size, len(res.Text), cost, "ok", map[string]any{"attachments": len(atts), "audio": len(audio), "in_tokens": res.InTokens, "out_tokens": res.OutTokens, "stream": true})
		send(map[string]any{"done": true, "usage": map[string]int{"input_tokens": res.InTokens, "output_tokens": res.OutTokens}, "cost_estimate_usd": cost})
		return
	}
	res, err := h.ops.Analyze(ctx, m, system, prompt, atts, maxTokens)
	if err != nil {
		h.done(c, m, size, 0, 0, "error", nil)
		h.fail(w, err)
		return
	}
	cost := aimm.EstimateTokens(m, res.InTokens, res.OutTokens) + extraCost
	h.done(c, m, size, len(res.Text), cost, "ok", map[string]any{"attachments": len(atts), "audio": len(audio), "in_tokens": res.InTokens, "out_tokens": res.OutTokens})
	respondJSON(w, http.StatusOK, map[string]any{"model": m.ID, "text": res.Text, "usage": map[string]int{"input_tokens": res.InTokens, "output_tokens": res.OutTokens}, "cost_estimate_usd": cost})
}

// transcribeNow runs a Transcribe job and waits for it (used by chat audio attachments, short clips only).
func (h *AIMMHandler) transcribeNow(ctx context.Context, c *aiCall, data []byte, format, lang string, minutes float64) (string, error) {
	if format == "" {
		return "", aimm.BadInput("audio format not recognized: use mp3, wav, m4a, flac, ogg, webm")
	}
	job, err := h.tr.Start(ctx, aimm.StartRequest{Data: data, Format: format, Lang: lang, ProjectID: c.projectID.String(), UserID: userID(c), EstMinutes: minutes})
	if err != nil {
		return "", err
	}
	for i := 0; i < 60; i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if job, err = h.tr.Poll(ctx, job); err != nil {
			return "", err
		}
		switch job.Status {
		case "completed":
			h.quota.Add(ctx, c.scope(), job.CostUSD)
			return job.Result.Text, nil
		case "failed":
			return "", aimm.BadInput("the audio could not be transcribed: %s", job.Error)
		}
	}
	return "", context.DeadlineExceeded
}

func userID(c *aiCall) string {
	if c.user == nil {
		return ""
	}
	return c.user.ID.String()
}

// ---- speech to text (asynchronous job) ----

// Transcribe answers POST .../ai/transcribe (multipart: file, or JSON/multipart file_source=bucket/key): lang?, diarize?, speakers?, save_to?, save_format?.
// It returns 202 with the job; GET .../ai/jobs/{id} gives the state and, when done, the transcript with timestamps.
func (h *AIMMHandler) Transcribe(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapSTT)
	if !ok {
		return
	}
	if h.tr == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "transcription needs CAPSULE_AI_STAGE_BUCKET (an S3 bucket for Amazon Transcribe)")
		return
	}
	f, ok := h.parseForm(w, r, aimm.MaxAudioBytes+(2<<20))
	if !ok {
		return
	}
	m, ok := h.pickModel(w, r, aimm.CapSTT, f.str("model"), "transcribe")
	if !ok {
		return
	}
	fl, err := h.file(r.Context(), c, f, "file", aimm.MaxAudioBytes)
	if err != nil {
		h.fail(w, err)
		return
	}
	if fl == nil {
		h.fail(w, aimm.BadInput("send the audio as the file field, or as file_source=bucket/key"))
		return
	}
	format := aimm.AudioFormat(fl.Name)
	if format == "" {
		format = aimm.AudioFormat(fl.ContentType)
	}
	est := aimm.EstimateMinutes(m, float64(len(fl.Data))/16000/60)
	if !h.budget(w, c, est) {
		return
	}
	saveFmt := strings.ToLower(f.str("save_format"))
	if saveFmt == "" {
		saveFmt = "json"
	}
	if f.str("save_to") != "" {
		if _, _, ok := splitRef(f.str("save_to")); !ok && !strings.Contains(f.str("save_to"), "/") && f.str("save_to") == "" {
			h.fail(w, aimm.BadInput("save_to must look like bucket/key"))
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	job, err := h.tr.Start(ctx, aimm.StartRequest{Data: fl.Data, Format: format, Lang: f.str("lang"), Diarize: f.flag("diarize"), MaxSpeakers: f.num("speakers", 0),
		ProjectID: c.projectID.String(), UserID: userID(c), SaveTo: f.str("save_to"), SaveFmt: saveFmt, EstMinutes: float64(len(fl.Data)) / 16000 / 60})
	if err != nil {
		h.done(c, m, len(fl.Data), 0, 0, "error", nil)
		h.fail(w, err)
		return
	}
	h.done(c, m, len(fl.Data), 0, job.CostUSD, "ok", map[string]any{"job_id": job.ID, "diarize": job.Diarize})
	respondJSON(w, http.StatusAccepted, map[string]any{"job": job, "poll": "jobs/" + job.ID})
}

// Job answers GET .../ai/jobs/{jobID}[?format=txt|srt|vtt|json]. While running it answers the state; when completed with a format it
// answers the rendered transcript as a file.
func (h *AIMMHandler) Job(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapChat)
	if !ok {
		return
	}
	if h.tr == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "transcription is not configured")
		return
	}
	job, err := h.tr.Load(r.Context(), chi.URLParam(r, "jobID"))
	if err != nil || job.ProjectID != c.projectID.String() {
		h.fail(w, aimm.ErrJobNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	before := job.Status
	if job, err = h.tr.Poll(ctx, job); err != nil {
		h.fail(w, err)
		return
	}
	if job.Status == "completed" && before != "completed" {
		h.quota.Add(context.WithoutCancel(ctx), c.scope(), 0) // spend was recorded when the job started (estimate); no double count
	}
	if job.Status == "completed" && job.SaveTo != "" && job.Saved == "" {
		body, ct, rerr := job.Result.Render(job.SaveFmt)
		if rerr == nil {
			name := "transcript-" + job.ID[:8] + "." + map[string]string{"": "txt", "txt": "txt", "text": "txt", "srt": "srt", "vtt": "vtt", "json": "json"}[job.SaveFmt]
			if p, serr := h.save(ctx, c, job.SaveTo, name, body, ct); serr == nil {
				job.Saved = p
				_ = h.tr.Save(ctx, job)
			} else {
				h.logger.Warn("saving transcript failed", "err", serr.Error())
			}
		}
	}
	if fm := r.URL.Query().Get("format"); fm != "" && job.Status == "completed" {
		body, ct, err := job.Result.Render(fm)
		if err != nil {
			h.fail(w, err)
			return
		}
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(body)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"job": job})
}

// ---- text to speech ----

// Speech answers POST .../ai/speech {text, model?, voice?, lang?, format?, rate?, save_to?}: audio in the body, or JSON with base64 when
// Accept is application/json or save_to is given.
func (h *AIMMHandler) Speech(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapTTS)
	if !ok {
		return
	}
	if h.polly == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "text to speech is not configured")
		return
	}
	f, ok := h.parseForm(w, r, 1<<20)
	if !ok {
		return
	}
	m, ok := h.pickModel(w, r, aimm.CapTTS, f.str("model"), "polly-neural")
	if !ok {
		return
	}
	chars := len([]rune(f.str("text")))
	est := aimm.EstimateSpeech(m, chars)
	if !h.budget(w, c, est) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	sp, err := aimm.Speak(ctx, h.polly, m, aimm.SpeakRequest{Text: f.str("text"), Voice: f.str("voice"), Lang: f.str("lang"), Format: f.str("format"), Rate: f.str("rate")})
	if err != nil {
		h.done(c, m, chars, 0, 0, "error", nil)
		h.fail(w, err)
		return
	}
	cost := aimm.EstimateSpeech(m, sp.Chars)
	extra := map[string]any{"voice": sp.Voice, "chars": sp.Chars}
	w.Header().Set("X-Capsule-Cost-USD", strconv.FormatFloat(cost, 'f', -1, 64))
	w.Header().Set("X-Capsule-Chars", strconv.Itoa(sp.Chars))
	if f.str("save_to") != "" || strings.Contains(r.Header.Get("Accept"), "application/json") {
		saved := ""
		if f.str("save_to") != "" {
			if saved, err = h.save(ctx, c, f.str("save_to"), "speech-"+uuid.NewString()[:8]+"."+sp.Format, sp.Audio, sp.ContentType); err != nil {
				h.done(c, m, chars, len(sp.Audio), cost, "ok", extra)
				h.fail(w, err)
				return
			}
		}
		h.done(c, m, chars, len(sp.Audio), cost, "ok", extra)
		out := map[string]any{"model": m.ID, "voice": sp.Voice, "format": sp.Format, "content_type": sp.ContentType, "chars": sp.Chars, "cost_estimate_usd": cost, "saved_to": saved}
		if saved == "" || !strings.EqualFold(f.str("inline"), "false") {
			out["audio_base64"] = base64.StdEncoding.EncodeToString(sp.Audio)
		}
		respondJSON(w, http.StatusOK, out)
		return
	}
	h.done(c, m, chars, len(sp.Audio), cost, "ok", extra)
	w.Header().Set("Content-Type", sp.ContentType)
	_, _ = w.Write(sp.Audio)
}

// Voices answers GET .../ai/voices?lang=es-US.
func (h *AIMMHandler) Voices(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.begin(w, r, aimm.CapTTS); !ok {
		return
	}
	vs, err := aimm.ListVoices(r.Context(), h.polly, r.URL.Query().Get("lang"))
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": vs})
}

// ---- images ----

// Images answers POST .../ai/images (multipart or JSON): prompt?, model?, n?, size?, format?, and the files image and mask (or *_source).
// With no image it generates from the prompt; with an image it edits it with the chosen model (or operation=inpaint|erase-object|
// remove-background|search-replace|search-recolor|outpaint|style-transfer|style-guide|fast-upscale|conservative-upscale|creative-upscale).
// Service fields (search_prompt, select_prompt, negative_prompt, seed, aspect_ratio, control_strength, fidelity, left, right, up, down) pass through;
// style_image is a file.
func (h *AIMMHandler) Images(w http.ResponseWriter, r *http.Request) {
	f, ok := h.parseForm(w, r, 40<<20)
	if !ok {
		return
	}
	c, ok := h.begin(w, r, aimm.CapImageGenerate)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	img, err := h.file(ctx, c, f, "image", 10<<20)
	if err != nil {
		h.fail(w, err)
		return
	}
	mask, err := h.file(ctx, c, f, "mask", 10<<20)
	if err != nil {
		h.fail(w, err)
		return
	}
	style, err := h.file(ctx, c, f, "style_image", 10<<20)
	if err != nil {
		h.fail(w, err)
		return
	}
	modelID := f.str("model")
	if modelID == "" && f.str("operation") != "" {
		modelID = "stability-" + f.str("operation")
	}
	cap := aimm.CapImageGenerate
	if img != nil {
		cap = aimm.CapImageEdit
	}
	c.cap = cap
	var defaults []string
	if img == nil {
		defaults = []string{"stability-image-control-sketch"}
	} else if mask != nil {
		defaults = []string{"stability-image-inpaint"}
	} else {
		defaults = []string{"stability-image-remove-background"}
	}
	m, ok := h.pickModel(w, r, cap, modelID, defaults...)
	if !ok {
		return
	}
	n := f.num("n", 1)
	est := aimm.EstimateImages(m, n)
	if !h.budget(w, c, est) {
		return
	}
	extra := map[string]any{}
	for _, k := range []string{"search_prompt", "select_prompt", "negative_prompt", "aspect_ratio", "style_preset"} {
		if v := f.str(k); v != "" {
			extra[k] = v
		}
	}
	for _, k := range []string{"seed", "left", "right", "up", "down", "grow_mask"} {
		if v := f.str(k); v != "" {
			if x, err := strconv.Atoi(v); err == nil {
				extra[k] = x
			}
		}
	}
	for _, k := range []string{"control_strength", "fidelity"} {
		if v := f.str(k); v != "" {
			if x, err := strconv.ParseFloat(v, 64); err == nil {
				extra[k] = x
			}
		}
	}
	if style != nil {
		extra["style_image"] = base64.StdEncoding.EncodeToString(style.Data)
	}
	req := aimm.ImageRequest{Prompt: f.str("prompt"), N: n, Size: f.str("size"), Format: strings.ToLower(f.str("format")), Extra: extra}
	if img != nil {
		req.Image = img.Data
	}
	if mask != nil {
		req.Mask = mask.Data
	}
	in := len(req.Prompt) + len(req.Image) + len(req.Mask)
	outs, err := h.ops.ImageOp(ctx, m, req)
	if err != nil {
		h.done(c, m, in, 0, 0, "error", nil)
		h.fail(w, err)
		return
	}
	cost := aimm.EstimateImages(m, len(outs))
	type imgOut struct {
		Format string `json:"format"`
		Seed   int64  `json:"seed,omitempty"`
		B64    string `json:"b64,omitempty"`
		Saved  string `json:"saved_to,omitempty"`
	}
	res := make([]imgOut, 0, len(outs))
	total := 0
	for i, o := range outs {
		total += len(o.Data)
		x := imgOut{Format: o.Format, Seed: o.Seed}
		if t := f.str("save_to"); t != "" {
			p, err := h.save(ctx, c, t, fmt.Sprintf("image-%s-%d.%s", uuid.NewString()[:6], i+1, o.Format), o.Data, "image/"+o.Format)
			if err != nil {
				h.done(c, m, in, total, cost, "ok", nil)
				h.fail(w, err)
				return
			}
			x.Saved = p
		}
		if x.Saved == "" || !strings.EqualFold(f.str("inline"), "false") {
			x.B64 = base64.StdEncoding.EncodeToString(o.Data)
		}
		res = append(res, x)
	}
	h.done(c, m, in, total, cost, "ok", map[string]any{"images": len(outs), "edit": img != nil})
	respondJSON(w, http.StatusOK, map[string]any{"model": m.ID, "capability": cap, "images": res, "cost_estimate_usd": cost})
}

// ---- speech to speech ----

// Talk answers POST .../ai/talk (multipart: audio as WAV PCM16 mono or raw PCM16 16 kHz; model?, voice?, system?): one spoken turn.
// It returns what the model heard, its text answer and its spoken answer as base64 WAV (24 kHz).
func (h *AIMMHandler) Talk(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapSpeechToSpeech)
	if !ok {
		return
	}
	f, ok := h.parseForm(w, r, 20<<20)
	if !ok {
		return
	}
	m, ok := h.pickModel(w, r, aimm.CapSpeechToSpeech, f.str("model"), "nova-2-sonic", "nova-2-5-sonic")
	if !ok {
		return
	}
	fl, err := h.file(r.Context(), c, f, "audio", 20<<20)
	if err != nil {
		h.fail(w, err)
		return
	}
	if fl == nil {
		h.fail(w, aimm.BadInput("send the speech as the audio field (WAV PCM16 mono, or raw PCM16 at 16 kHz)"))
		return
	}
	pcm := fl.Data
	if len(pcm) > 12 && string(pcm[0:4]) == "RIFF" {
		var rate int
		if pcm, rate, err = aimm.PCMFromWAV(fl.Data); err != nil {
			h.fail(w, err)
			return
		}
		pcm = aimm.Resample16(pcm, rate)
	}
	minutes := float64(len(pcm)) / (aimm.SonicInRate * 2) / 60
	est := aimm.EstimateMinutes(m, minutes+0.5)
	if !h.budget(w, c, est) {
		return
	}
	res, err := aimm.TalkFile(r.Context(), h.bidi, m, aimm.SonicConfig{Voice: f.str("voice"), System: f.str("system")}, pcm, 90*time.Second)
	if err != nil {
		h.done(c, m, len(pcm), 0, 0, "error", nil)
		h.fail(w, err)
		return
	}
	outMin := float64(len(res.Audio)) / (aimm.SonicOutRate * 2) / 60
	cost := aimm.EstimateMinutes(m, minutes+outMin)
	wav := aimm.WAV(res.Audio, aimm.SonicOutRate)
	saved := ""
	if t := f.str("save_to"); t != "" {
		if saved, err = h.save(r.Context(), c, t, "talk-"+uuid.NewString()[:8]+".wav", wav, "audio/wav"); err != nil {
			h.done(c, m, len(pcm), len(wav), cost, "ok", nil)
			h.fail(w, err)
			return
		}
	}
	h.done(c, m, len(pcm), len(wav), cost, "ok", map[string]any{"in_tokens": res.InTokens, "out_tokens": res.OutTokens})
	respondJSON(w, http.StatusOK, map[string]any{"model": m.ID, "heard": res.Heard, "answer": res.Answer, "audio_base64": base64.StdEncoding.EncodeToString(wav),
		"audio_content_type": "audio/wav", "audio_seconds": float64(len(res.Audio)) / (aimm.SonicOutRate * 2), "saved_to": saved,
		"usage": map[string]int{"input_tokens": res.InTokens, "output_tokens": res.OutTokens}, "cost_estimate_usd": cost})
}

// ---- speech to speech over WebSocket ----

const talkTicketTTL = 60

type talkTicket struct {
	OrgID, ProjectID, UserID string
	Model, Voice, System     string
}

// TalkTicket answers POST .../ai/talk/ticket {model?, voice?, system?}: a single-use ticket (60 s) to open GET /ai/talk/ws?ticket=... from
// a browser, which cannot set an Authorization header on a WebSocket.
func (h *AIMMHandler) TalkTicket(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, aimm.CapSpeechToSpeech)
	if !ok {
		return
	}
	if h.cache == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "live voice needs the platform cache")
		return
	}
	f, ok := h.parseForm(w, r, 64<<10)
	if !ok {
		return
	}
	m, ok := h.pickModel(w, r, aimm.CapSpeechToSpeech, f.str("model"), "nova-2-sonic", "nova-2-5-sonic")
	if !ok {
		return
	}
	if !h.budget(w, c, aimm.EstimateMinutes(m, 1)) {
		return
	}
	var raw [18]byte
	_, _ = rand.Read(raw[:])
	tk := base64.RawURLEncoding.EncodeToString(raw[:])
	b, _ := json.Marshal(talkTicket{OrgID: c.orgID.String(), ProjectID: c.projectID.String(), UserID: userID(c), Model: m.ID, Voice: f.str("voice"), System: f.str("system")})
	if err := h.cache.Set(r.Context(), "ai:talk:"+tk, string(b), talkTicketTTL); err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ticket": tk, "expires_in": talkTicketTTL, "ws": "/api/v1/ai/talk/ws?ticket=" + tk, "model": m.ID,
		"protocol": "send binary frames of PCM16 16 kHz mono; receive JSON text frames {type:text,role,text} and binary frames of PCM16 24 kHz mono; send the text frame \"end\" to finish"})
}

// TalkWS serves GET /ai/talk/ws?ticket=...: the live conversation. Public route; the ticket is the credential.
func (h *AIMMHandler) TalkWS(w http.ResponseWriter, r *http.Request) {
	tk := r.URL.Query().Get("ticket")
	if tk == "" || h.cache == nil || h.bidi == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid ticket")
		return
	}
	raw, err := h.cache.Get(r.Context(), "ai:talk:"+tk)
	if err != nil || raw == "" {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid ticket")
		return
	}
	_ = h.cache.Del(r.Context(), "ai:talk:"+tk) // single use
	var t talkTicket
	if json.Unmarshal([]byte(raw), &t) != nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid ticket")
		return
	}
	m, ok := h.cat.Get(r.Context(), t.Model)
	if !ok || !m.Available {
		respondError(w, http.StatusConflict, "MODEL_UNAVAILABLE", "model not available")
		return
	}
	orgID, _ := uuid.Parse(t.OrgID)
	projectID, _ := uuid.Parse(t.ProjectID)
	uid, _ := uuid.Parse(t.UserID)
	call := &aiCall{user: &domain.User{ID: uid}, orgID: orgID, projectID: projectID, cap: aimm.CapSpeechToSpeech, started: time.Now(), r: r}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: false, OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(256 << 10)
	const maxSession = 5 * time.Minute
	ctx, cancel := context.WithTimeout(r.Context(), maxSession)
	defer cancel()
	s, err := aimm.StartSonic(ctx, h.bidi, m, aimm.SonicConfig{Voice: t.Voice, System: t.System})
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, truncate(err.Error(), 100))
		return
	}
	defer s.Close()
	var inBytes, outBytes int
	go func() { // model -> browser
		for ev := range s.Events {
			switch ev.Kind {
			case "audio":
				outBytes += len(ev.Audio)
				if conn.Write(ctx, websocket.MessageBinary, ev.Audio) != nil {
					cancel()
					return
				}
			case "text":
				b, _ := json.Marshal(map[string]string{"type": "text", "role": strings.ToLower(ev.Role), "text": ev.Text})
				_ = conn.Write(ctx, websocket.MessageText, b)
			case "error":
				b, _ := json.Marshal(map[string]string{"type": "error", "message": ev.Err.Error()})
				_ = conn.Write(ctx, websocket.MessageText, b)
				cancel()
				return
			}
		}
		cancel()
	}()
loop:
	for { // browser -> model
		typ, data, err := conn.Read(ctx)
		if err != nil {
			break
		}
		if typ == websocket.MessageText {
			if string(data) == "end" {
				break loop
			}
			continue
		}
		inBytes += len(data)
		if err := s.Audio(data); err != nil {
			break
		}
	}
	_ = s.EndInput()
	_ = s.Finish()
	minutes := time.Since(call.started).Minutes()
	cost := aimm.EstimateMinutes(m, minutes)
	h.done(call, m, inBytes, outBytes, cost, "ok", map[string]any{"live": true, "seconds": int(time.Since(call.started).Seconds())})
	_ = conn.Close(websocket.StatusNormalClosure, "bye")
}

var _ = strings.TrimSpace

// SetLegacyModels sets the handler that answers GET /ai/models when no capability is asked (the original model list).
func (h *AIMMHandler) SetLegacyModels(f http.HandlerFunc) { h.legacyModels = f }

// ModelsRoute serves GET /ai/models and GET /models: the capability catalog when ?capability= or ?catalog= is present, else the legacy list.
func (h *AIMMHandler) ModelsRoute(w http.ResponseWriter, r *http.Request) {
	if h.legacyModels == nil || r.URL.Query().Get("capability") != "" || r.URL.Query().Get("catalog") != "" {
		h.Models(w, r)
		return
	}
	h.legacyModels(w, r)
}
