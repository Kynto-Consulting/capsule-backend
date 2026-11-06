package server

import (
	"os"
	"strconv"

	"github.com/kynto/capsule/backend/internal/aimm"
	"github.com/kynto/capsule/backend/internal/server/handlers"
)

// newAIMMHandler wires the multimodal AI surface (docs/AI_MULTIMODAL.md).
//
//	CAPSULE_AI_STAGE_BUCKET        S3 bucket where audio waits for Amazon Transcribe (default capsule-artifacts-<account>); "off" disables transcription
//	CAPSULE_AI_DAILY_BUDGET_USD    estimated spend per project and UTC day (default 5; 0 = no cap)
func newAIMMHandler(deps Deps, logger interface{ Warn(string, ...any) }) *handlers.AIMMHandler {
	c := deps.AWSClients
	if c == nil { // no AWS: the routes stay mounted and answer 503
		return handlers.NewAIMMHandler(handlers.AIMMDeps{Orgs: deps.OrgRepo, Catalog: aimm.NewCatalog(nil, ""), Quota: &aimm.Quota{KV: aimm.NewMemKV()}})
	}
	kv := aimm.KV(aimm.NewMemKV())
	if deps.CacheStore != nil {
		kv = deps.CacheStore
	}
	daily := 5.0
	if v := os.Getenv("CAPSULE_AI_DAILY_BUDGET_USD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			daily = f
		}
	}
	d := handlers.AIMMDeps{
		Orgs: deps.OrgRepo, Catalog: aimm.NewCatalog(c.BedrockCtl, c.Region), Ops: &aimm.Ops{RT: c.Bedrock},
		Polly: c.Polly, Bidi: c.Bedrock, Quota: &aimm.Quota{KV: kv, DailyUSD: daily}, Cache: deps.CacheStore,
	}
	bucket := os.Getenv("CAPSULE_AI_STAGE_BUCKET")
	if bucket == "" && c.Account != "" {
		bucket = "capsule-artifacts-" + c.Account
	}
	if bucket != "" && bucket != "off" {
		d.Trans = &aimm.Transcriber{API: c.Transcribe, Stage: &aimm.S3Stage{API: c.S3, Bucket: bucket}, Jobs: kv}
	} else {
		logger.Warn("ai transcription disabled: no staging bucket (CAPSULE_AI_STAGE_BUCKET)")
	}
	if o := deps.Objstore; o != nil {
		d.Buckets = handlers.NewObjstoreBuckets(handlers.ObjstoreConfig{Store: o.Store, Repo: o.Repo, InternalEndpoint: o.InternalEndpoint, Region: o.Region})
	}
	return handlers.NewAIMMHandler(d)
}
