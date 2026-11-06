package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/netaccess"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// AccessApplier applies the desired CIDR set of one database to the host firewall.
// *netaccess.Reconciler implements it.
type AccessApplier interface {
	ReconcileDB(ctx context.Context, dbID uuid.UUID, port int, cidrs []string) error
}

// DatabaseAccessHandler manages who can reach a database from the internet.
type DatabaseAccessHandler struct {
	authzHolder
	dbs       domain.DatabaseRepository
	orgs      domain.OrganizationRepository
	projects  domain.ProjectRepository
	rules     domain.DatabaseAccessRepository
	applier   AccessApplier // nil => feature not configured (501)
	host      string
	tlsDir    string
	secretKey string
	logger    *slog.Logger
}

func NewDatabaseAccessHandler(
	dbs domain.DatabaseRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	rules domain.DatabaseAccessRepository,
	applier AccessApplier,
	host, tlsDir, secretKey string,
	logger *slog.Logger,
) *DatabaseAccessHandler {
	return &DatabaseAccessHandler{
		dbs: dbs, orgs: orgs, projects: projects, rules: rules, applier: applier,
		host: host, tlsDir: tlsDir, secretKey: secretKey, logger: logger,
	}
}

// Cleanup revokes every firewall rule of a deleted database and drops its stored rules.
func (h *DatabaseAccessHandler) Cleanup(db *domain.Database) {
	if h == nil || h.applier == nil || db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.applier.ReconcileDB(ctx, db.ID, 0, nil); err != nil {
		// Stored rules stay so the startup reconcile can retry; it revokes
		// orphaned rules of deleted databases.
		h.logger.Warn("revoking database access rules failed", "db_id", db.ID, "error", err)
		return
	}
	if err := h.rules.DeleteAll(ctx, db.ID); err != nil {
		h.logger.Warn("deleting database access rules failed", "db_id", db.ID, "error", err)
	}
}

type accessCtx struct {
	user *domain.User
	role string
	db   *domain.Database
}

// load validates ids, feature availability, membership and that the database
// belongs to the project/org. It writes the error response itself.
func (h *DatabaseAccessHandler) load(w http.ResponseWriter, r *http.Request, write bool) (*accessCtx, bool) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return nil, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return nil, false
	}
	dbID, err := uuid.Parse(chi.URLParam(r, "dbID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid database id")
		return nil, false
	}
	if h.applier == nil {
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED",
			"database network access management is not configured on this server (APP_SECURITY_GROUP_ID is not set)")
		return nil, false
	}
	role, err := h.orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return nil, false
	}
	act := authz.ProjectRead
	if write {
		act = authz.ProjectNetwork
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, act) {
		return nil, false
	}
	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return nil, false
	}
	db, err := h.dbs.GetByID(r.Context(), dbID)
	if err == domain.ErrNotFound || (err == nil && (db.OrgID != orgID || db.ProjectID == nil || *db.ProjectID != projectID)) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "database not found")
		return nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get database")
		return nil, false
	}
	if db.Tier == "prod" || db.Engine == "s3" || db.Engine == "objstore" {
		respondError(w, http.StatusBadRequest, "UNSUPPORTED", "network access rules only apply to databases hosted on the Capsule host")
		return nil, false
	}
	if write && db.Port <= 0 {
		respondError(w, http.StatusConflict, "DB_NOT_READY", "database is not yet available")
		return nil, false
	}
	return &accessCtx{user: user, role: role, db: db}, true
}

type connectionInfo struct {
	Engine      string `json:"engine"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Database    string `json:"database"`
	Username    string `json:"username"`
	SSLMode     string `json:"ssl_mode,omitempty"`
	URLTemplate string `json:"url_template"`
}

type accessResponse struct {
	DatabaseID uuid.UUID                    `json:"database_id"`
	Host       string                       `json:"host"`
	Port       int                          `json:"port"`
	MaxRules   int                          `json:"max_rules"`
	Rules      []*domain.DatabaseAccessRule `json:"rules"`
	Connection connectionInfo               `json:"connection"`
}

func (h *DatabaseAccessHandler) connection(db *domain.Database) connectionInfo {
	host := db.Host
	if h.host != "" {
		host = h.host
	}
	username := "capsuleadmin"
	if len(db.CredentialsEnc) > 0 {
		if plain, err := crypto.Decrypt(db.CredentialsEnc, h.secretKey); err == nil {
			var c struct {
				Username string `json:"username"`
			}
			if json.Unmarshal(plain, &c) == nil && c.Username != "" {
				username = c.Username
			}
		}
	}
	info := connectionInfo{Engine: db.Engine, Host: host, Port: db.Port, Database: db.DBName, Username: username}
	scheme := db.Engine
	suffix := ""
	switch db.Engine {
	case "postgres":
		scheme = "postgres"
		suffix = postgresSSLQuery(h.tlsDir)
		info.SSLMode = strings.TrimPrefix(suffix, "?sslmode=")
	case "mariadb":
		scheme = "mysql"
	}
	info.URLTemplate = scheme + "://" + username + ":<password>@" + host + ":" + strconv.Itoa(db.Port) + "/" + db.DBName + suffix
	return info
}

func (h *DatabaseAccessHandler) respondState(w http.ResponseWriter, status int, ac *accessCtx, rules []*domain.DatabaseAccessRule) {
	if rules == nil {
		rules = []*domain.DatabaseAccessRule{}
	}
	conn := h.connection(ac.db)
	respondJSON(w, status, accessResponse{
		DatabaseID: ac.db.ID, Host: conn.Host, Port: ac.db.Port,
		MaxRules: netaccess.MaxRulesPerDatabase, Rules: rules, Connection: conn,
	})
}

// GET .../databases/{dbID}/access
func (h *DatabaseAccessHandler) List(w http.ResponseWriter, r *http.Request) {
	ac, ok := h.load(w, r, false)
	if !ok {
		return
	}
	rules, err := h.rules.List(r.Context(), ac.db.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list access rules")
		return
	}
	h.respondState(w, http.StatusOK, ac, rules)
}

type accessRuleInput struct {
	CIDR        string `json:"cidr"`
	Description string `json:"description"`
}

// checkCIDR validates one input and enforces the public-access gate. It writes the error itself.
func checkCIDR(w http.ResponseWriter, raw string, allowPublic bool, role string) (string, bool) {
	cidr, err := netaccess.NormalizeCIDR(raw, true)
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_CIDR", err.Error())
		return "", false
	}
	if netaccess.IsPublicCIDR(cidr) {
		if !allowPublic {
			respondError(w, http.StatusBadRequest, "PUBLIC_NOT_ALLOWED",
				cidr+" exposes the database to the whole internet; send \"allow_public\": true to confirm")
			return "", false
		}
		if !isOrgAdmin(role) {
			respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can open a database to the public internet")
			return "", false
		}
	}
	return cidr, true
}

func cidrList(rules []*domain.DatabaseAccessRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.CIDR)
	}
	return out
}

// applyError maps a reconcile failure to a response.
func (h *DatabaseAccessHandler) applyError(w http.ResponseWriter, dbID uuid.UUID, err error) {
	h.logger.Error("applying database access rules failed", "db_id", dbID, "error", err)
	if errors.Is(err, netaccess.ErrRuleLimit) {
		respondError(w, http.StatusConflict, "SG_RULE_LIMIT", err.Error())
		return
	}
	respondError(w, http.StatusBadGateway, "FIREWALL_ERROR", "could not apply the rules to the host firewall: "+err.Error()+" (nothing was changed)")
}

// resync re-applies the stored state after a failed persist (best effort).
func (h *DatabaseAccessHandler) resync(ctx context.Context, db *domain.Database) {
	rules, err := h.rules.List(ctx, db.ID)
	if err != nil {
		return
	}
	if err := h.applier.ReconcileDB(ctx, db.ID, db.Port, cidrList(rules)); err != nil {
		h.logger.Warn("resync after failed persist failed", "db_id", db.ID, "error", err)
	}
}

// PUT .../databases/{dbID}/access   {"rules":[{"cidr","description"}], "cidrs":["..."], "allow_public":false}
func (h *DatabaseAccessHandler) Replace(w http.ResponseWriter, r *http.Request) {
	ac, ok := h.load(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Rules       []accessRuleInput `json:"rules"`
		CIDRs       []string          `json:"cidrs"`
		AllowPublic bool              `json:"allow_public"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	inputs := append([]accessRuleInput(nil), body.Rules...)
	for _, c := range body.CIDRs {
		inputs = append(inputs, accessRuleInput{CIDR: c})
	}

	seen := map[string]bool{}
	var rules []*domain.DatabaseAccessRule
	for _, in := range inputs {
		cidr, ok := checkCIDR(w, in.CIDR, body.AllowPublic, ac.role)
		if !ok {
			return
		}
		if seen[cidr] {
			continue
		}
		seen[cidr] = true
		rules = append(rules, &domain.DatabaseAccessRule{DatabaseID: ac.db.ID, CIDR: cidr, Description: strings.TrimSpace(in.Description)})
	}
	if len(rules) > netaccess.MaxRulesPerDatabase {
		respondError(w, http.StatusUnprocessableEntity, "LIMIT_EXCEEDED", "a database can have at most 25 access rules")
		return
	}

	if err := h.applier.ReconcileDB(r.Context(), ac.db.ID, ac.db.Port, cidrList(rules)); err != nil {
		h.applyError(w, ac.db.ID, err)
		return
	}
	stored, err := h.rules.Replace(r.Context(), ac.db.ID, rules, ac.user.ID)
	if err != nil {
		h.logger.Error("persisting access rules failed", "db_id", ac.db.ID, "error", err)
		h.resync(r.Context(), ac.db)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save access rules")
		return
	}
	h.respondState(w, http.StatusOK, ac, stored)
}

// POST .../databases/{dbID}/access   {"cidr","description","allow_public"}
func (h *DatabaseAccessHandler) Add(w http.ResponseWriter, r *http.Request) {
	ac, ok := h.load(w, r, true)
	if !ok {
		return
	}
	var body struct {
		accessRuleInput
		AllowPublic bool `json:"allow_public"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	cidr, ok := checkCIDR(w, body.CIDR, body.AllowPublic, ac.role)
	if !ok {
		return
	}
	existing, err := h.rules.List(r.Context(), ac.db.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list access rules")
		return
	}
	for _, e := range existing {
		if e.CIDR == cidr {
			respondError(w, http.StatusConflict, "ALREADY_EXISTS", "that CIDR already has access")
			return
		}
	}
	if len(existing) >= netaccess.MaxRulesPerDatabase {
		respondError(w, http.StatusUnprocessableEntity, "LIMIT_EXCEEDED", "a database can have at most 25 access rules")
		return
	}

	if err := h.applier.ReconcileDB(r.Context(), ac.db.ID, ac.db.Port, append(cidrList(existing), cidr)); err != nil {
		h.applyError(w, ac.db.ID, err)
		return
	}
	userID := ac.user.ID
	rule, err := h.rules.Add(r.Context(), &domain.DatabaseAccessRule{
		DatabaseID: ac.db.ID, CIDR: cidr, Description: strings.TrimSpace(body.Description), CreatedBy: &userID,
	}, netaccess.MaxRulesPerDatabase)
	if err != nil {
		h.resync(r.Context(), ac.db)
		switch {
		case errors.Is(err, domain.ErrConflict):
			respondError(w, http.StatusConflict, "ALREADY_EXISTS", "that CIDR already has access")
		case errors.Is(err, domain.ErrRuleLimit):
			respondError(w, http.StatusUnprocessableEntity, "LIMIT_EXCEEDED", "a database can have at most 25 access rules")
		default:
			h.logger.Error("persisting access rule failed", "db_id", ac.db.ID, "error", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save access rule")
		}
		return
	}
	respondJSON(w, http.StatusCreated, rule)
}

// DELETE .../databases/{dbID}/access/{ruleID}
func (h *DatabaseAccessHandler) Remove(w http.ResponseWriter, r *http.Request) {
	ac, ok := h.load(w, r, true)
	if !ok {
		return
	}
	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule id")
		return
	}
	existing, err := h.rules.List(r.Context(), ac.db.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list access rules")
		return
	}
	var keep []string
	found := false
	for _, e := range existing {
		if e.ID == ruleID {
			found = true
			continue
		}
		keep = append(keep, e.CIDR)
	}
	if !found {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "access rule not found")
		return
	}
	if err := h.applier.ReconcileDB(r.Context(), ac.db.ID, ac.db.Port, keep); err != nil {
		h.applyError(w, ac.db.ID, err)
		return
	}
	if err := h.rules.Delete(r.Context(), ac.db.ID, ruleID); err != nil && err != domain.ErrNotFound {
		h.logger.Error("deleting access rule failed", "db_id", ac.db.ID, "error", err)
		h.resync(r.Context(), ac.db)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete access rule")
		return
	}
	respondNoContent(w)
}
