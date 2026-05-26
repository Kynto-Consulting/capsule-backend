package pricing

import (
	"fmt"
)

type CostItem struct {
	Name string  `json:"name"`
	Cost float64 `json:"cost"`
	Unit string  `json:"unit"`
}

type CostEstimate struct {
	MonthlyUSD float64    `json:"monthly_usd"`
	AnnualUSD  float64    `json:"annual_usd"`
	Breakdown  []CostItem `json:"breakdown"`
}

func EstimateRDS(engine string, instanceClass string, storageGB int, multiAZ bool) CostEstimate {
	var compute float64
	// Defaults to us-east-1 on-demand pricing
	switch instanceClass {
	case "db.t3.micro":
		compute = 15.33
	case "db.t3.small":
		compute = 30.66
	case "db.t3.medium":
		compute = 61.32
	case "db.r6g.large":
		compute = 175.20
	default:
		compute = 15.33
	}

	if multiAZ {
		compute *= 2.0
	}

	storageRate := 0.115 // gp3 storage rate per GB
	storageCost := float64(storageGB) * storageRate

	backupRate := 0.023 // backup storage rate per GB
	backupCost := float64(storageGB) * backupRate

	total := compute + storageCost + backupCost

	engineName := "PostgreSQL"
	if engine == "mysql" {
		engineName = "MySQL"
	}

	return CostEstimate{
		MonthlyUSD: total,
		AnnualUSD:  total * 12.0,
		Breakdown: []CostItem{
			{Name: fmt.Sprintf("%s %s (Compute)", engineName, instanceClass), Cost: compute, Unit: "month"},
			{Name: fmt.Sprintf("gp3 Storage (%d GB)", storageGB), Cost: storageCost, Unit: "month"},
			{Name: "Automated Backups (7d retention)", Cost: backupCost, Unit: "month"},
		},
	}
}

func EstimateEC2(instanceType string, count int) CostEstimate {
	var rate float64
	switch instanceType {
	case "t3.nano":
		rate = 3.80
	case "t3.micro":
		rate = 7.60
	case "t3.small":
		rate = 15.00
	case "t3.medium":
		rate = 30.00
	case "t3.large":
		rate = 60.00
	default:
		rate = 15.00
	}

	computeCost := rate * float64(count)
	albCost := 22.00 // shared ALB estimate
	ecrCost := 0.10  // 1 GB storage average
	total := computeCost + albCost + ecrCost

	return CostEstimate{
		MonthlyUSD: total,
		AnnualUSD:  total * 12.0,
		Breakdown: []CostItem{
			{Name: fmt.Sprintf("EC2 %s (%d replicas)", instanceType, count), Cost: computeCost, Unit: "month"},
			{Name: "Application Load Balancer (Shared)", Cost: albCost, Unit: "month"},
			{Name: "ECR Image Storage (1 GB avg)", Cost: ecrCost, Unit: "month"},
		},
	}
}

func EstimateS3(storageGB int, requestsK int) CostEstimate {
	storageRate := 0.023 // Standard S3 rate per GB
	storageCost := float64(storageGB) * storageRate

	// Requests standard: GET $0.0004 per 1,000, PUT $0.005 per 1,000
	requestRate := 0.0004
	requestCost := float64(requestsK) * requestRate

	cloudfrontRate := 0.085 // Average CloudFront bandwidth rate per GB
	cloudfrontCost := float64(storageGB) * cloudfrontRate

	total := storageCost + requestCost + cloudfrontCost

	return CostEstimate{
		MonthlyUSD: total,
		AnnualUSD:  total * 12.0,
		Breakdown: []CostItem{
			{Name: fmt.Sprintf("S3 Storage (%d GB)", storageGB), Cost: storageCost, Unit: "month"},
			{Name: fmt.Sprintf("API Requests (%dK GETs)", requestsK), Cost: requestCost, Unit: "month"},
			{Name: "CloudFront CDN (Est. 10 GB Outbound)", Cost: cloudfrontCost, Unit: "month"},
		},
	}
}

func EstimateLambda(requestsM int, avgDurationMs int) CostEstimate {
	// AWS Lambda pricing: $0.20 per million requests + $0.0000166667 per GB-second
	// Assuming 512MB RAM allocation
	requestCost := float64(requestsM) * 0.20
	
	gbSeconds := float64(requestsM) * 1000000.0 * (float64(avgDurationMs) / 1000.0) * 0.5
	computeCost := gbSeconds * 0.0000166667

	apiGatewayCost := float64(requestsM) * 3.50
	cwLogsCost := 0.50

	total := requestCost + computeCost + apiGatewayCost + cwLogsCost

	return CostEstimate{
		MonthlyUSD: total,
		AnnualUSD:  total * 12.0,
		Breakdown: []CostItem{
			{Name: fmt.Sprintf("AWS Lambda Requests (%dM)", requestsM), Cost: requestCost, Unit: "month"},
			{Name: fmt.Sprintf("AWS Lambda Compute (%dms avg)", avgDurationMs), Cost: computeCost, Unit: "month"},
			{Name: "HTTP API Gateway (1M calls)", Cost: apiGatewayCost, Unit: "month"},
			{Name: "CloudWatch Logs", Cost: cwLogsCost, Unit: "month"},
		},
	}
}
