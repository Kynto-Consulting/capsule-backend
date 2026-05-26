package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/kynto/capsule/backend/internal/pricing"
)

type PricingHandler struct{}

func NewPricingHandler() *PricingHandler {
	return &PricingHandler{}
}

func (h *PricingHandler) Estimate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceType string          `json:"resource_type"`
		Config       json.RawMessage `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	var estimate pricing.CostEstimate

	switch req.ResourceType {
	case "rds":
		var conf struct {
			Engine        string `json:"engine"`
			InstanceClass string `json:"instance_class"`
			StorageGB     int    `json:"storage_gb"`
			MultiAZ       bool   `json:"multi_az"`
		}
		if err := json.Unmarshal(req.Config, &conf); err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_CONFIG", "invalid rds configuration parameters")
			return
		}
		if conf.StorageGB <= 0 {
			conf.StorageGB = 20
		}
		estimate = pricing.EstimateRDS(conf.Engine, conf.InstanceClass, conf.StorageGB, conf.MultiAZ)

	case "ec2":
		var conf struct {
			InstanceType string `json:"instance_type"`
			Count        int    `json:"count"`
		}
		if err := json.Unmarshal(req.Config, &conf); err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_CONFIG", "invalid ec2 configuration parameters")
			return
		}
		if conf.Count <= 0 {
			conf.Count = 1
		}
		estimate = pricing.EstimateEC2(conf.InstanceType, conf.Count)

	case "s3":
		var conf struct {
			StorageGB int `json:"storage_gb"`
			RequestsK int `json:"requests_k"`
		}
		if err := json.Unmarshal(req.Config, &conf); err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_CONFIG", "invalid s3 configuration parameters")
			return
		}
		if conf.StorageGB <= 0 {
			conf.StorageGB = 10
		}
		if conf.RequestsK <= 0 {
			conf.RequestsK = 100
		}
		estimate = pricing.EstimateS3(conf.StorageGB, conf.RequestsK)

	case "lambda":
		var conf struct {
			RequestsM     int `json:"requests_m"`
			AvgDurationMs int `json:"avg_duration_ms"`
		}
		if err := json.Unmarshal(req.Config, &conf); err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_CONFIG", "invalid lambda configuration parameters")
			return
		}
		if conf.RequestsM <= 0 {
			conf.RequestsM = 1
		}
		if conf.AvgDurationMs <= 0 {
			conf.AvgDurationMs = 100
		}
		estimate = pricing.EstimateLambda(conf.RequestsM, conf.AvgDurationMs)

	default:
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid resource type; must be rds, ec2, s3, or lambda")
		return
	}

	respondJSON(w, http.StatusOK, estimate)
}
