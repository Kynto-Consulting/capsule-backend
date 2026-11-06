package main

import (
	"fmt"
	"sort"
	"strings"
)

// Classes of routes whose authorization is not (only) an authz.Action found in the handler body. They were
// read from the handlers by hand on 2026-11-04; the extractor fails if a rule matches no route (stale) or if
// a route ends with neither an action nor a class (a new route must be classified here or use authz).
//
//	action                        authz.Service decides with the old actions listed (found in the handler)
//	public                        no authentication
//	oidc-protocol                 OpenID Connect endpoint: the protocol validates the client or the bearer token
//	own-credentials               no session: the handler validates its own credential (AI key or cap_ token)
//	public-secret                 reachable without a session but guarded by a secret or a signature
//	public-dataplane              traffic of the deployed applications (proxy)
//	self                          authenticated; acts only on the caller's own data
//	any-user                      authenticated; no further check and no organization data
//	org-member                    caller belongs to the organization (any role, readonly included)
//	org-admin                     caller is organization owner or admin
//	org-admin-or-self             organization owner/admin, or the member removing themself
//	org-admin+owner-fields        owner or admin; only the owner (owner_id) may change the name
//	org-owner                     caller is the organization owner (owner_id)
//	org-admin-or-platform-admin   OIDC client management: org owner/admin of the client's org, or platform admin
//	platform-admin                users.role = admin
//	no-check                      authenticated and nothing else (legacy gap G8)
type rule struct {
	handler string // exact handler label (as in the golden file)
	class   string
	actions []string // actions to record when the decision is made through an interface the extractor cannot follow
	note    string
}

var rules = []rule{
	// --- OpenID Connect provider (public protocol endpoints)
	{handler: "handlers.OIDCHandler.Discovery", class: "oidc-protocol"},
	{handler: "handlers.OIDCHandler.Preflight", class: "oidc-protocol"},
	{handler: "handlers.OIDCHandler.JWKS", class: "oidc-protocol"},
	{handler: "handlers.OIDCHandler.Authorize", class: "oidc-protocol"},
	{handler: "handlers.OIDCHandler.Token", class: "oidc-protocol"},
	{handler: "handlers.OIDCHandler.UserInfo", class: "oidc-protocol"},
	{handler: "handlers.OIDCHandler.RequestInfo", class: "self"},
	{handler: "handlers.OIDCHandler.Approve", class: "self"},
	{handler: "handlers.OIDCHandler.Deny", class: "oidc-protocol", note: "no session: the request id is the secret"},
	{handler: "handlers.OIDCHandler.CreateClient", class: "org-admin-or-platform-admin", note: "oauthclient:manage; first-party clients are platform admin only"},
	{handler: "handlers.OIDCHandler.ListClients", class: "org-admin-or-platform-admin"},
	{handler: "handlers.OIDCHandler.DeleteClient", class: "org-admin-or-platform-admin"},
	{handler: "handlers.OIDCHandler.UpdateClient", class: "org-admin-or-platform-admin"},

	// --- public and secret-guarded endpoints
	{handler: "handlers.Health", class: "public"},
	{handler: "handlers.VPNFnHandler.CreateVPN", class: "action", actions: []string{"project.network"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.DeleteVPN", class: "action", actions: []string{"project.network"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.SetVPNEnabled", class: "action", actions: []string{"project.network"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.ListVPN", class: "action", actions: []string{"project.read"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.GetVPN", class: "action", actions: []string{"project.read"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.VPNEvents", class: "action", actions: []string{"project.read"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.DeployFn", class: "action", actions: []string{"project.ops"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.DeleteFn", class: "action", actions: []string{"project.ops"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.ListFn", class: "action", actions: []string{"project.read"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.GetFn", class: "action", actions: []string{"project.read"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.RunFn", class: "action", actions: []string{"project.ops"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.EnqueueFn", class: "action", actions: []string{"project.ops"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.CancelRun", class: "action", actions: []string{"project.ops"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.ListRuns", class: "action", actions: []string{"project.read"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.GetRun", class: "action", actions: []string{"project.read"}, note: "vpn connector"},
	{handler: "handlers.VPNFnHandler.Introspect", class: "public-secret", note: "the capfn_ token is the credential; unknown tokens answer active=false"},
	{handler: "handlers.VPNFnHandler.AgentClaim", class: "public-secret", note: "work node: capnode_ token (hash in fn_nodes), outbound only"},
	{handler: "handlers.VPNFnHandler.AgentSync", class: "public-secret", note: "work node: capnode_ token (hash in fn_nodes), outbound only"},
	{handler: "handlers.VPNFnHandler.AgentFinish", class: "public-secret", note: "work node: capnode_ token (hash in fn_nodes), outbound only"},
	{handler: "handlers.VPNFnHandler.AgentTunnelStatus", class: "public-secret", note: "work node: capnode_ token (hash in fn_nodes), outbound only"},
	{handler: "handlers.VPNFnHandler.RelayNode", class: "public-secret", note: "work node: capnode_ token; only for tunnels of the Lambda runs assigned to it"},
	{handler: "handlers.VPNFnHandler.RelayConnect", class: "public-secret", note: "Lambda: capfn_ run token of a function with a tunnel; destinations outside the declared CIDRs are denied and audited"},
	{handler: "server.newRouter.func1", class: "public-secret", note: "/metrics: METRICS_TOKEN when set"},
	{handler: "handlers.GitHandler.Webhook", class: "public-secret", note: "HMAC signature"},
	{handler: "api.Service.handleRoutes", class: "public-secret", note: "gateway data plane: CAPSULE_GW_SECRET"},
	{handler: "api.Service.handleKeys", class: "public-secret", note: "gateway data plane: CAPSULE_GW_SECRET"},
	{handler: "handlers.TLSAskHandler.ServeHTTP", class: "public-dataplane", note: "Caddy on_demand_tls ask: host-only answer, closed by Caddy blocking /internal/*"},
	{handler: "handlers.ProxyHandler.ProxyBySlug", class: "public-dataplane"},
	{handler: "handlers.ProxyHandler.Proxy", class: "public-dataplane"},
	{handler: "handlers.AuthHandler.Register", class: "public"},
	{handler: "handlers.AuthHandler.Login", class: "public"},
	{handler: "handlers.AuthHandler.Refresh", class: "public"},
	{handler: "handlers.AuthHandler.GetOnboardingStatus", class: "public"},
	{handler: "handlers.AuthHandler.VerifyOnboarding", class: "public"},
	{handler: "handlers.AIHandler.Chat", class: "own-credentials"},
	{handler: "handlers.AIMMHandler.ModelsRoute", class: "public", note: "capability catalog or the legacy list"},
	{handler: "handlers.AIMMHandler.TalkWS", class: "public-secret", note: "single-use ticket from POST ./ai/talk/ticket"},
	{handler: "handlers.AIMMHandler.Chat", class: "action", actions: []string{"project.read"}, note: "multimodal AI"},
	{handler: "handlers.AIMMHandler.Embeddings", class: "action", actions: []string{"project.read"}, note: "multimodal AI"},
	{handler: "handlers.AIMMHandler.SearchEmbeddings", class: "action", actions: []string{"project.read"}, note: "multimodal AI"},
	{handler: "handlers.AIMMHandler.Rerank", class: "action", actions: []string{"project.read"}, note: "multimodal AI"},
	{handler: "handlers.AIMMHandler.Job", class: "action", actions: []string{"project.read"}, note: "multimodal AI"},
	{handler: "handlers.AIMMHandler.Usage", class: "action", actions: []string{"project.read"}, note: "multimodal AI"},
	{handler: "handlers.AIMMHandler.Transcribe", class: "action", actions: []string{"project.ops"}, note: "multimodal AI (storage:presign)"},
	{handler: "handlers.AIMMHandler.Speech", class: "action", actions: []string{"project.ops"}, note: "multimodal AI (storage:presign)"},
	{handler: "handlers.AIMMHandler.Voices", class: "action", actions: []string{"project.ops"}, note: "multimodal AI (storage:presign)"},
	{handler: "handlers.AIMMHandler.Images", class: "action", actions: []string{"project.ops"}, note: "multimodal AI (storage:presign)"},
	{handler: "handlers.AIMMHandler.Talk", class: "action", actions: []string{"project.ops"}, note: "multimodal AI (storage:presign)"},
	{handler: "handlers.AIMMHandler.TalkTicket", class: "action", actions: []string{"project.ops"}, note: "multimodal AI (storage:presign)"},
	{handler: "handlers.AIHandler.SkillDoc", class: "public"},

	// --- the caller's own data
	{handler: "handlers.AuthHandler.Me", class: "self"},
	{handler: "handlers.AuthHandler.Logout", class: "self"},
	{handler: "handlers.APITokenHandler.List", class: "self"},
	{handler: "handlers.APITokenHandler.Revoke", class: "self"},
	{handler: "handlers.APITokenHandler.Update", class: "self"},
	{handler: "handlers.NotificationsHandler.list", class: "self"},
	{handler: "handlers.NotificationsHandler.mark", class: "self"},
	{handler: "handlers.NotificationsHandler.getSettings", class: "self"},
	{handler: "handlers.NotificationsHandler.putSettings", class: "self"},
	{handler: "handlers.GitTokensHandler.List", class: "self"},
	{handler: "handlers.GitTokensHandler.RevokeSession", class: "self"},
	{handler: "handlers.GitTokensHandler.Revoke", class: "self"},
	{handler: "handlers.GitTokensHandler.ListKeys", class: "self"},
	{handler: "handlers.GitTokensHandler.AddKey", class: "self"},
	{handler: "handlers.GitTokensHandler.DeleteKey", class: "self"},
	{handler: "handlers.AIHandler.CreateKey", class: "self"},
	{handler: "handlers.AIHandler.ListKeys", class: "self"},
	{handler: "handlers.AIHandler.UpdateKey", class: "self"},
	{handler: "handlers.AIHandler.RevokeKey", class: "self"},
	{handler: "handlers.OrgHandler.List", class: "self", note: "lists the caller's own organizations"},

	// --- any authenticated user
	{handler: "handlers.OrgHandler.Create", class: "any-user", note: "the creator becomes owner"},
	{handler: "handlers.AIHandler.Dockerfile", class: "any-user"},
	{handler: "handlers.AIHandler.ExplainFailure", class: "any-user"},
	{handler: "handlers.AIHandler.OptimizeCosts", class: "any-user"},
	{handler: "handlers.PricingHandler.Estimate", class: "any-user"},
	{handler: "handlers.PlatformCapabilities", class: "any-user"},
	{handler: "handlers.NetworkHandler.MyIP", class: "any-user"},
	{handler: "handlers.BillingHandler.GetBillingSummary", class: "no-check", note: "G8: no role check in the handler"},

	// --- organization level
	{handler: "handlers.OrgHandler.Get", class: "org-member"},
	{handler: "handlers.OrgHandler.Update", class: "org-admin+owner-fields", note: "owner or admin; name is owner only; project_access_mode is owner or admin"},
	{handler: "handlers.OrgHandler.Delete", class: "org-owner"},
	{handler: "handlers.OrgMembersHandler.List", class: "org-member"},
	{handler: "handlers.OrgMembersHandler.Invite", class: "org-admin"},
	{handler: "handlers.OrgMembersHandler.UpdateRole", class: "org-admin", note: "an owner target is 403"},
	{handler: "handlers.OrgMembersHandler.Remove", class: "org-admin-or-self", note: "an owner target is 403"},
	{handler: "handlers.ProjectHandler.Create", class: "org-member", note: "G7: readonly may create projects"},
	{handler: "handlers.ProjectHandler.List", class: "org-member", note: "result filtered by authz FilterProjects"},
	{handler: "handlers.OrgEnvHandler.List", class: "org-member", note: "?reveal=true needs owner or admin"},
	{handler: "handlers.OrgEnvHandler.Set", class: "org-admin"},
	{handler: "handlers.OrgEnvHandler.Delete", class: "org-admin"},
	{handler: "handlers.EnvironmentsHandler.ApprovalsPending", class: "org-member"},
	{handler: "handlers.auditHandler.list", class: "org-admin", note: "audit:read; ?format=csv is audit:export"},
	{handler: "handlers.gitAPI.orgCiSecretsList", class: "org-admin"},
	{handler: "handlers.gitAPI.orgCiSecretPut", class: "org-admin"},
	{handler: "handlers.gitAPI.orgCiSecretDelete", class: "org-admin"},
	{handler: "handlers.gitAPI.orgCiVarsList", class: "org-member"},
	{handler: "handlers.gitAPI.orgCiVarPut", class: "org-admin"},
	{handler: "handlers.gitAPI.orgCiVarDelete", class: "org-admin"},
	{handler: "handlers.gitAPI.runnersList", class: "org-member"},
	{handler: "handlers.gitImportAPI.importCreate", class: "org-admin"},
	{handler: "handlers.gitImportAPI.importGet", class: "org-admin"},
	{handler: "api.Service.handlePolicyGet", class: "org-member"},
	{handler: "handlers.StorageHandler.GetOrgQuota", class: "org-member"},
	{handler: "handlers.StorageHandler.PutOrgQuota", class: "org-admin"},
	{handler: "api.Service.handlePolicySet", class: "org-admin"},
	{handler: "handlers.DatabaseHandler.ListByOrg", class: "org-member", note: "G7; result filtered by Visibility"},
	{handler: "handlers.DatabaseHandler.CreateOrgLevel", class: "org-member", note: "G7: readonly may create"},
	{handler: "handlers.DomainHandler.ListByOrg", class: "org-member", note: "result filtered by Visibility"},
	{handler: "handlers.DomainHandler.CreateOrgLevel", class: "org-member", note: "G7: readonly may create"},

	// --- platform admin
	{handler: "gitsync.MountGitsync.func1", class: "platform-admin", note: "POST /git/admin/reconcile"},
	{handler: "handlers.RecoverHandler.Platform", class: "platform-admin"},
	{handler: "handlers.RecoverHandler.Get", class: "platform-admin"},
	{handler: "handlers.BackupHandler.PlatformGet", class: "platform-admin"},
	{handler: "handlers.BackupHandler.PlatformRun", class: "platform-admin"},
	{handler: "handlers.BackupHandler.PlatformVerify", class: "platform-admin"},
	{handler: "handlers.AdminHandler.ListUsers", class: "platform-admin"},
	{handler: "handlers.AdminHandler.CreateUser", class: "platform-admin"},
	{handler: "handlers.AdminHandler.SuspendUser", class: "platform-admin"},
	{handler: "handlers.AdminHandler.UnsuspendUser", class: "platform-admin"},
	{handler: "handlers.AdminHandler.SetUserRole", class: "platform-admin"},
	{handler: "handlers.AdminHandler.DeleteUser", class: "platform-admin"},

	// --- decided through an interface the extractor cannot follow (cmd/server wires gitAuthorizer / AuthzAuthorizer:
	//     CanManage -> project.ops, CanDeploy -> project.read; see handlers/git.go scope())
	{handler: "handlers.GitHandler.Get", class: "action", actions: []string{"project.read"}, note: "via ProjectAuthorizer.CanDeploy"},
	{handler: "handlers.GitHandler.Previews", class: "action", actions: []string{"project.read"}, note: "via ProjectAuthorizer.CanDeploy"},
	{handler: "handlers.GitHandler.Put", class: "action", actions: []string{"project.ops"}, note: "via ProjectAuthorizer.CanManage"},
	{handler: "handlers.GitHandler.Delete", class: "action", actions: []string{"project.ops"}, note: "via ProjectAuthorizer.CanManage"},
	{handler: "handlers.GitHandler.Test", class: "action", actions: []string{"project.ops"}, note: "via ProjectAuthorizer.CanManage"},
}

func applyClasses(rows []Row) ([]Row, error) {
	used := make([]bool, len(rules))
	var problems []string
	for i := range rows {
		r := &rows[i]
		matched := -1
		for j, ru := range rules {
			if ru.handler == r.Handler {
				matched = j
				used[j] = true
			}
		}
		switch {
		case matched >= 0:
			ru := rules[matched]
			if len(r.Actions) > 0 && ru.class != "action" {
				problems = append(problems, fmt.Sprintf("%s %s: handler checks %v but is classified %s", r.Method, r.Path, r.Actions, ru.class))
				continue
			}
			r.Class = ru.class
			if ru.class == "public-secret" {
				r.Auth = "secret"
			}
			if len(ru.actions) > 0 {
				r.Actions = append([]string(nil), ru.actions...)
			}
		case r.Class == "" && strings.HasPrefix(r.Handler, "handlers.accessAPI."):
			// Routes of the atomic permissions API (P4): they have no legacy action; routePermissions in
			// internal/server/routeperms.go holds the atom each one requires.
			r.Class = "access-api"
		case r.Class == "":
			problems = append(problems, fmt.Sprintf("%s %s [%s]: no old action found and no class in classes.go", r.Method, r.Path, r.Handler))
		}
	}
	for i := range rows {
		if strings.HasPrefix(rows[i].Path, "/internal/") {
			rows[i].Auth = "secret" // shared-secret endpoints (Caddy forward_auth, gateway data plane)
		}
	}
	for j, ru := range rules {
		if !used[j] {
			problems = append(problems, fmt.Sprintf("stale rule: no route uses handler %s", ru.handler))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%d problems:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return rows, nil
}
