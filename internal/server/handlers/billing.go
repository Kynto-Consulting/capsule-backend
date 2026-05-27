package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type BillingHandler struct {
	dbs domain.DatabaseRepository
}

func NewBillingHandler(dbs domain.DatabaseRepository) *BillingHandler {
	return &BillingHandler{dbs: dbs}
}

func (h *BillingHandler) GetBillingSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := middleware.GetUser(ctx)
	projects, rdsDbs, s3Buckets, domains, err := h.dbs.GetUserStats(ctx, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to calculate global stats: "+err.Error())
		return
	}

	// Calculate realistic AWS pricing breakdown based on active Capsule infrastructure
	projectCost := float64(projects) * 5.00
	rdsCost := float64(rdsDbs) * 15.00
	s3Cost := float64(s3Buckets) * 2.00
	domainCost := float64(domains) * 0.50
	baseInfrastructureCost := 12.50 // Base ALB, VPC endpoint, NAT Gateway costs
	sesMailingCost := 8.00          // SES verified identities base allocation

	totalSpend := projectCost + rdsCost + s3Cost + domainCost + baseInfrastructureCost + sesMailingCost
	currency := "USD"
	
	// Master educational/starter AWS credits pool allocation
	const initialCredits = 1000.00
	remainingCredits := initialCredits - totalSpend
	if remainingCredits < 0 {
		remainingCredits = 0
	}

	currentMonth := time.Now().Format("January 2006")
	creditExpiration := time.Now().AddDate(1, 0, 0).Format("2006-01-02")

	breakdown := []map[string]any{
		{
			"service": "Amazon EC2 (Serverless)",
			"cost":    projectCost + baseInfrastructureCost,
			"details": fmt.Sprintf("%d Active Serverless App Runtime Containers & Core ALB Infrastructure", projects),
		},
		{
			"service": "Amazon RDS (PostgreSQL)",
			"cost":    rdsCost,
			"details": fmt.Sprintf("%d Active Relational DB Instance(s) (db.t4g.micro class)", rdsDbs),
		},
		{
			"service": "Amazon S3 (Simple Storage)",
			"cost":    s3Cost,
			"details": fmt.Sprintf("%d Active Storage Bucket(s) for Media & Static Hosting", s3Buckets),
		},
		{
			"service": "Amazon Route53 (DNS Mapping)",
			"cost":    domainCost,
			"details": fmt.Sprintf("%d Active Custom Domain Record(s) with automated SSL mapping", domains),
		},
		{
			"service": "Amazon SES (Simple Email)",
			"cost":    sesMailingCost,
			"details": "Automated session mailing validation and sending quotas",
		},
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"total_spend":       totalSpend,
		"currency":          currency,
		"period":            currentMonth,
		"remaining_credits": remainingCredits,
		"credit_expiration": creditExpiration,
		"active_resources": map[string]int{
			"app_servers":    projects,
			"rds_databases":  rdsDbs,
			"s3_buckets":     s3Buckets,
			"custom_domains": domains,
		},
		"breakdown": breakdown,
	})
}
