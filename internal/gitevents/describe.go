package gitevents

import (
	"fmt"
	"net/url"
	"strings"
)

// Summary is the human rendering of an event shared by notifications, Slack, Discord and email.
// Texts are plain (no markup): each channel escapes them for its own format.
type Summary struct {
	Title string
	Body  string // extra lines, may be empty
	URL   string // dashboard link, may be empty
	Level string // info | success | warning | danger
}

func s(e Event, key string) string {
	if v, ok := e.Data[key]; ok {
		switch t := v.(type) {
		case string:
			return t
		case int:
			return fmt.Sprint(t)
		case int64:
			return fmt.Sprint(t)
		case float64:
			return fmt.Sprint(int64(t))
		}
	}
	return ""
}

func who(e Event) string {
	if e.Actor != "" {
		return e.Actor
	}
	return "Alguien"
}

// Link builds the dashboard URL of an event (base = frontend origin, no trailing slash).
func Link(base string, e Event) string {
	base = strings.TrimRight(base, "/")
	if base == "" || e.OrgSlug == "" || e.ProjectSlug == "" {
		return ""
	}
	repo := base + "/git/" + url.PathEscape(e.OrgSlug) + "/" + url.PathEscape(e.ProjectSlug)
	switch {
	case strings.HasPrefix(e.Name, "pr."):
		if n := s(e, "pr"); n != "" {
			return repo + "/pulls/" + url.PathEscape(n)
		}
		return repo + "/pulls"
	case e.Name == CheckCompleted || e.Name == WorkflowRunCompleted:
		return repo + "/actions"
	case strings.HasPrefix(e.Name, "security."):
		return repo + "/security"
	case e.Name == ApprovalRequested || e.Name == ApprovalDecided:
		return base + "/approvals"
	case strings.HasPrefix(e.Name, "deployment.") || e.Name == PromotionCompleted:
		return repo + "/environments"
	case e.Name == ProtectionChanged || e.Name == MemberChanged:
		return repo + "/settings"
	case e.Name == GitPush:
		if sha := s(e, "sha"); sha != "" {
			return repo + "/commit/" + url.PathEscape(sha)
		}
	}
	return repo
}

// Describe renders e in Spanish. base is the frontend origin used for links ("" = no links).
func Describe(base string, e Event) Summary {
	repo := e.OrgSlug + "/" + e.ProjectSlug
	if e.OrgSlug == "" {
		repo = "el proyecto"
	}
	sum := Summary{URL: Link(base, e), Level: "info"}
	pr := func() string {
		t := s(e, "title")
		if t != "" {
			return fmt.Sprintf("#%s %s", s(e, "pr"), t)
		}
		return "#" + s(e, "pr")
	}
	switch e.Name {
	case GitPush:
		sum.Title = fmt.Sprintf("%s hizo push a %s en %s", who(e), s(e, "branch"), repo)
		sum.Body = s(e, "message")
	case GitBranchCreated:
		sum.Title = fmt.Sprintf("%s creo la rama %s en %s", who(e), s(e, "branch"), repo)
	case GitBranchDeleted:
		sum.Title = fmt.Sprintf("%s elimino la rama %s en %s", who(e), s(e, "branch"), repo)
	case PROpened:
		sum.Title = fmt.Sprintf("%s abrio el PR %s en %s", who(e), pr(), repo)
	case PRUpdated:
		sum.Title = fmt.Sprintf("PR %s actualizado en %s", pr(), repo)
	case PRReadyForReview:
		sum.Title = fmt.Sprintf("El PR %s esta listo para revision en %s", pr(), repo)
	case PRReviewSubmitted:
		switch s(e, "state") {
		case "approved":
			sum.Title, sum.Level = fmt.Sprintf("%s aprobo el PR %s", s(e, "reviewer"), pr()), "success"
		case "changes_requested":
			sum.Title, sum.Level = fmt.Sprintf("%s pidio cambios en el PR %s", s(e, "reviewer"), pr()), "warning"
		default:
			sum.Title = fmt.Sprintf("%s comento la revision del PR %s", s(e, "reviewer"), pr())
		}
		sum.Body = s(e, "body")
	case PRReviewRequested:
		sum.Title = fmt.Sprintf("Se pidio la revision de %s en el PR %s", s(e, "requested_reviewer"), pr())
	case PRMerged:
		sum.Title, sum.Level = fmt.Sprintf("PR %s fusionado en %s", pr(), repo), "success"
	case PRClosed:
		sum.Title = fmt.Sprintf("PR %s cerrado sin fusionar en %s", pr(), repo)
	case PRAutoMergeEnabled:
		sum.Title = fmt.Sprintf("Auto-merge programado para el PR %s", pr())
	case CheckCompleted:
		sum.Title = fmt.Sprintf("Check %s: %s", s(e, "context"), s(e, "state"))
		sum.Level = levelFor(s(e, "state"))
		sum.Body = s(e, "description")
	case WorkflowRunCompleted:
		sum.Title = fmt.Sprintf("Ejecucion de CI %s terminada: %s", firstNonEmpty(s(e, "name"), s(e, "run_id")), s(e, "conclusion"))
		sum.Level = levelFor(s(e, "conclusion"))
	case DeploymentCreated:
		sum.Title = fmt.Sprintf("Despliegue creado en %s", repo)
	case DeploymentSucceeded:
		sum.Title, sum.Level = fmt.Sprintf("Despliegue correcto en %s", repo), "success"
	case DeploymentFailed:
		sum.Title, sum.Level = fmt.Sprintf("Despliegue fallido en %s", repo), "danger"
		sum.Body = s(e, "error")
	case ApprovalRequested:
		sum.Title, sum.Level = fmt.Sprintf("Promocion a %s espera tu aprobacion en %s", firstNonEmpty(s(e, "environment"), "un entorno"), repo), "warning"
	case ApprovalDecided:
		if s(e, "decision") == "rejected" {
			sum.Title, sum.Level = fmt.Sprintf("Promocion a %s rechazada en %s", firstNonEmpty(s(e, "environment"), "un entorno"), repo), "danger"
		} else {
			sum.Title, sum.Level = fmt.Sprintf("Promocion a %s aprobada en %s", firstNonEmpty(s(e, "environment"), "un entorno"), repo), "success"
		}
	case PromotionCompleted:
		sum.Title = fmt.Sprintf("Promocion a %s terminada en %s", firstNonEmpty(s(e, "environment"), "un entorno"), repo)
		sum.Level = levelFor(s(e, "status"))
	case PreviewReady:
		sum.Title, sum.Level = fmt.Sprintf("Preview listo en %s", repo), "success"
		if u := s(e, "preview_url"); u != "" {
			sum.Body = u
		}
	case PreviewDeleted:
		sum.Title = fmt.Sprintf("Preview eliminado en %s", repo)
	case SecurityAlertCreated:
		sum.Title, sum.Level = fmt.Sprintf("Nueva alerta de seguridad (%s) en %s", firstNonEmpty(s(e, "severity"), "sin severidad"), repo), "danger"
		sum.Body = s(e, "rule")
	case SecurityAlertDismiss:
		sum.Title = fmt.Sprintf("Alerta de seguridad suprimida en %s", repo)
	case SecuritySuppExpiring:
		sum.Title, sum.Level = fmt.Sprintf("Una supresion de seguridad caduca en 7 dias en %s", repo), "warning"
	case SecurityPolicyBlock:
		sum.Title, sum.Level = fmt.Sprintf("La politica de seguridad bloqueo una operacion en %s", repo), "danger"
		sum.Body = s(e, "reason")
	case ProtectionChanged:
		sum.Title = fmt.Sprintf("%s cambio las reglas de proteccion de ramas en %s", who(e), repo)
	case MemberChanged:
		sum.Title = fmt.Sprintf("Cambio de rol en %s", repo)
	case BackupCompleted:
		sum.Title = fmt.Sprintf("Respaldo terminado en %s", repo)
		sum.Level = levelFor(s(e, "status"))
	case RecoveryCompleted:
		sum.Title = fmt.Sprintf("Recuperacion terminada en %s", repo)
		sum.Level = levelFor(s(e, "status"))
	case DeploymentConnWarn:
		sum.Title, sum.Level = fmt.Sprintf("El despliegue de %s usa conexiones internas sin enrutar", repo), "warning"
		sum.Body = s(e, "summary")
	case WebhookTest:
		sum.Title = "Prueba de webhook de Git Capsule"
		sum.Body = "Si ves este mensaje, el destino recibe las entregas."
	default:
		sum.Title = e.Name + " en " + repo
	}
	return sum
}

func levelFor(state string) string {
	switch strings.ToLower(state) {
	case "success", "succeeded", "ok", "completed":
		return "success"
	case "failure", "failed", "error":
		return "danger"
	case "cancelled", "skipped":
		return "warning"
	}
	return "info"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
