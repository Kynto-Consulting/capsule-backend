package service

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/pkg/crypto"
)

// EnvEntry is one resolved variable with the scope it was defined with.
type EnvEntry struct {
	Value string
	Scope string // build | runtime | both
}

// MergeEnvLayers merges variable layers; later layers win entirely (value and
// scope). Call as MergeEnvLayers(org, parentProject, project, deploy) so precedence
// is deploy > project > parent project (PR previews) > org.
func MergeEnvLayers(layers ...map[string]EnvEntry) map[string]EnvEntry {
	out := map[string]EnvEntry{}
	for _, l := range layers {
		for k, v := range l {
			out[k] = v
		}
	}
	return out
}

// FilterEnvByScope returns the entries visible to the given phase ("runtime" or
// "build"): scope == phase or scope == "both". Result is sorted by key.
func FilterEnvByScope(m map[string]EnvEntry, phase string) []KV {
	var out []KV
	for k, e := range m {
		if e.Scope == phase || e.Scope == "both" {
			out = append(out, KV{Key: k, Value: e.Value})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// KV is a key/value pair.
type KV struct{ Key, Value string }

func (w *DeployWorker) loadEnvTable(ctx context.Context, q string, id uuid.UUID) (map[string]EnvEntry, error) {
	rows, err := w.pool.Query(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]EnvEntry{}
	for rows.Next() {
		var k, scope string
		var enc []byte
		if err := rows.Scan(&k, &enc, &scope); err != nil {
			return nil, err
		}
		out[k] = EnvEntry{Value: w.decryptEnvValue(k, enc), Scope: scope}
	}
	return out, rows.Err()
}

// resolveEnv returns the effective variables for a deployment:
// deployment overrides > project variables > parent project variables (previews only) > org (account) variables.
func (w *DeployWorker) resolveEnv(ctx context.Context, deploymentID, projectID uuid.UUID) (map[string]EnvEntry, error) {
	var orgID uuid.UUID
	var parentID *uuid.UUID
	var org map[string]EnvEntry
	if err := w.pool.QueryRow(ctx, `SELECT org_id, parent_project_id FROM projects WHERE id = $1`, projectID).Scan(&orgID, &parentID); err == nil {
		org, err = w.loadEnvTable(ctx, `SELECT key, value_enc, scope FROM org_env_vars WHERE org_id = $1`, orgID)
		if err != nil {
			return nil, err
		}
	}
	parent := map[string]EnvEntry{}
	if parentID != nil { // PR preview: inherit the parent project variables as a layer below its own
		var perr error
		if parent, perr = w.loadEnvTable(ctx, `SELECT key, value_enc, scope FROM env_vars WHERE project_id = $1`, *parentID); perr != nil {
			return nil, perr
		}
	}
	proj, err := w.loadEnvTable(ctx, `SELECT key, value_enc, scope FROM env_vars WHERE project_id = $1`, projectID)
	if err != nil {
		return nil, err
	}

	deploy := map[string]EnvEntry{}
	var envEnc []byte
	if err := w.pool.QueryRow(ctx, `SELECT env_enc FROM deployments WHERE id = $1`, deploymentID).Scan(&envEnc); err == nil && len(envEnc) > 0 {
		plain, derr := crypto.Decrypt(envEnc, w.secretKey)
		if derr != nil {
			return nil, derr
		}
		var raw map[string]string
		if err := json.Unmarshal(plain, &raw); err != nil {
			return nil, err
		}
		for k, v := range raw {
			deploy[k] = EnvEntry{Value: v, Scope: "both"}
		}
	}
	return MergeEnvLayers(org, parent, proj, deploy), nil
}
