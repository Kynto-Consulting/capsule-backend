package fn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// MaxInvoke is AWS Lambda's hard limit per invocation (900 s); each batch is kept below it (docs/vpn-connector.md, section 7).
const (
	MaxInvoke  = 15 * time.Minute
	BatchSlice = 13 * time.Minute // a function that honours ctx.budget returns {"continue": cursor} before this
)

// LambdaAPI is the part of *lambda.Client the executor uses (the same client Capsule's deploy worker uses).
type LambdaAPI interface {
	CreateFunction(ctx context.Context, in *lambda.CreateFunctionInput, opts ...func(*lambda.Options)) (*lambda.CreateFunctionOutput, error)
	UpdateFunctionCode(ctx context.Context, in *lambda.UpdateFunctionCodeInput, opts ...func(*lambda.Options)) (*lambda.UpdateFunctionCodeOutput, error)
	UpdateFunctionConfiguration(ctx context.Context, in *lambda.UpdateFunctionConfigurationInput, opts ...func(*lambda.Options)) (*lambda.UpdateFunctionConfigurationOutput, error)
	Invoke(ctx context.Context, in *lambda.InvokeInput, opts ...func(*lambda.Options)) (*lambda.InvokeOutput, error)
	DeleteFunction(ctx context.Context, in *lambda.DeleteFunctionInput, opts ...func(*lambda.Options)) (*lambda.DeleteFunctionOutput, error)
	GetFunction(ctx context.Context, in *lambda.GetFunctionInput, opts ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error)
}

// LambdaExecutor runs functions as their own Lambda (`capsule-fn-<12 hex of the function id>`), with the role of the deploy worker.
type LambdaExecutor struct {
	API     LambdaAPI
	Account string
	Now     func() time.Time
	// Poll is how often Ensure checks that a created or updated Lambda is ready (default 2 s); ReadyWait caps it (default 5 min).
	Poll      time.Duration
	ReadyWait time.Duration
}

// LambdaName is the AWS function name of f.
func LambdaName(f *Function) string {
	return "capsule-fn-" + strings.ReplaceAll(f.ID.String(), "-", "")[:12]
}

// Ensure creates or updates the Lambda of f with its image, its memory and a per-invocation timeout capped at 15 minutes,
// and returns only when the Lambda can be invoked. AWS applies a create or an update asynchronously: invoking a Lambda in
// state Pending, or updating its configuration while its code update is InProgress, fails (ResourceConflictException), so
// every change is followed by a wait. Nothing is changed when the image and the limits are already the wanted ones.
// Secrets never go in Environment (visible in the AWS console): they travel in the Invoke payload.
func (e *LambdaExecutor) Ensure(ctx context.Context, f *Function, imageURI string) error {
	if imageURI == "" {
		return errors.New("the function has no image yet (its build has not finished)")
	}
	timeout := int32(f.TimeoutSeconds)
	if timeout > int32(MaxInvoke.Seconds()) {
		timeout = int32(MaxInvoke.Seconds())
	}
	name := LambdaName(f)
	cur, err := e.API.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String(name)})
	var nf *lambdatypes.ResourceNotFoundException
	if err != nil && !errors.As(err, &nf) {
		return err
	}
	if err != nil { // does not exist yet
		_, err = e.API.CreateFunction(ctx, &lambda.CreateFunctionInput{
			FunctionName: aws.String(name),
			Role:         aws.String("arn:aws:iam::" + e.Account + ":role/capsule-lambda-role"),
			PackageType:  lambdatypes.PackageTypeImage,
			Code:         &lambdatypes.FunctionCode{ImageUri: aws.String(imageURI)},
			MemorySize:   aws.Int32(int32(f.MemoryMB)),
			Timeout:      aws.Int32(timeout),
			Tags:         map[string]string{"capsule-fn": f.ID.String(), "capsule-project": f.ProjectID.String()},
		})
		if err != nil {
			return err
		}
		return e.waitReady(ctx, name)
	}
	if err := e.waitReady(ctx, name); err != nil { // a previous update may still be in progress
		return err
	}
	if cur.Code == nil || aws.ToString(cur.Code.ImageUri) != imageURI {
		if _, err := e.API.UpdateFunctionCode(ctx, &lambda.UpdateFunctionCodeInput{FunctionName: aws.String(name), ImageUri: aws.String(imageURI)}); err != nil {
			return err
		}
		if err := e.waitReady(ctx, name); err != nil {
			return err
		}
	}
	c := cur.Configuration
	if c == nil || aws.ToInt32(c.MemorySize) != int32(f.MemoryMB) || aws.ToInt32(c.Timeout) != timeout {
		if _, err := e.API.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
			FunctionName: aws.String(name), MemorySize: aws.Int32(int32(f.MemoryMB)), Timeout: aws.Int32(timeout)}); err != nil {
			return err
		}
		return e.waitReady(ctx, name)
	}
	return nil
}

// waitReady polls until the Lambda is Active and no update is in progress; Failed states end the wait with AWS's reason.
func (e *LambdaExecutor) waitReady(ctx context.Context, name string) error {
	poll, limit := e.Poll, e.ReadyWait
	if poll <= 0 {
		poll = 2 * time.Second
	}
	if limit <= 0 {
		limit = 5 * time.Minute
	}
	for waited := time.Duration(0); ; waited += poll {
		out, err := e.API.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String(name)})
		if err != nil {
			return err
		}
		c := out.Configuration
		if c == nil {
			return nil
		}
		switch {
		case c.State == lambdatypes.StateFailed:
			return fmt.Errorf("lambda %s failed: %s", name, aws.ToString(c.StateReason))
		case c.LastUpdateStatus == lambdatypes.LastUpdateStatusFailed:
			return fmt.Errorf("lambda %s update failed: %s", name, aws.ToString(c.LastUpdateStatusReason))
		case (c.State == "" || c.State == lambdatypes.StateActive) && c.LastUpdateStatus != lambdatypes.LastUpdateStatusInProgress:
			return nil
		}
		if waited >= limit {
			return fmt.Errorf("lambda %s is not ready after %s (state %s, update %s)", name, limit, c.State, c.LastUpdateStatus)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Remove deletes the Lambda of f (no cost remains). A Lambda that does not exist is not an error.
func (e *LambdaExecutor) Remove(ctx context.Context, f *Function) error {
	_, err := e.API.DeleteFunction(ctx, &lambda.DeleteFunctionInput{FunctionName: aws.String(LambdaName(f))})
	var nf *lambdatypes.ResourceNotFoundException
	if err != nil && !errors.As(err, &nf) {
		return err
	}
	return nil
}

// InvokePayload is what a function receives per batch. The token is minted by the backend per batch and dies with it.
type InvokePayload struct {
	RunID    string            `json:"run_id"`
	Function string            `json:"function"`
	Attempt  int               `json:"attempt"`
	Cursor   json.RawMessage   `json:"cursor,omitempty"`
	Payload  json.RawMessage   `json:"payload,omitempty"`
	Env      map[string]string `json:"env"` // CAPSULE_TOKEN, CAPSULE_SCOPES, CAPSULE_DB_*, CAPSULE_STORAGE_*, relay address
	BudgetMS int64             `json:"budget_ms"`
}

// BatchResult is the function's return value.
type BatchResult struct {
	Continue json.RawMessage `json:"continue,omitempty"`
	BytesIn  int64           `json:"bytes_in"`
	BytesOut int64           `json:"bytes_out"`
}

// Outcome is the end of a logical run (possibly many batches).
type Outcome struct {
	Status   string
	Batches  int
	BytesIn  int64
	BytesOut int64
	Log      string
}

// Run invokes the function in batches of at most BatchSlice until it stops asking to continue or the run's deadline passes.
// mint returns a fresh token environment for each batch (and revokes the previous one).
func (e *LambdaExecutor) Run(ctx context.Context, f *Function, run *Run, deadline time.Time, mint func(attempt int) (map[string]string, error)) (Outcome, error) {
	now := e.Now
	if now == nil {
		now = time.Now
	}
	out := Outcome{}
	var cursor json.RawMessage
	for attempt := 0; ; attempt++ {
		left := deadline.Sub(now())
		if left <= 0 {
			out.Status = RunTimeout
			out.Log += "run exceeded its total time and was stopped\n"
			return out, nil
		}
		budget := BatchSlice
		if left < budget {
			budget = left
		}
		env, err := mint(attempt)
		if err != nil {
			return out, err
		}
		body, _ := json.Marshal(InvokePayload{RunID: run.ID.String(), Function: f.Name, Attempt: attempt, Cursor: cursor, Payload: run.Payload, Env: env, BudgetMS: budget.Milliseconds()})
		ictx, cancel := context.WithTimeout(ctx, MaxInvoke+30*time.Second)
		res, err := e.API.Invoke(ictx, &lambda.InvokeInput{FunctionName: aws.String(LambdaName(f)), Payload: body, InvocationType: lambdatypes.InvocationTypeRequestResponse, LogType: lambdatypes.LogTypeTail})
		cancel()
		out.Batches++
		if err == nil && res.LogResult != nil { // the last 4 KB of the function's own log, for the run's log tail
			if b, derr := base64.StdEncoding.DecodeString(*res.LogResult); derr == nil {
				out.Log += string(b)
			}
		}
		if err != nil {
			return out, fmt.Errorf("invoke batch %d: %w", attempt, err)
		}
		if res.FunctionError != nil {
			out.Status = RunFailed
			out.Log += fmt.Sprintf("batch %d failed: %s %s\n", attempt, *res.FunctionError, string(res.Payload))
			return out, nil
		}
		var br BatchResult
		_ = json.Unmarshal(res.Payload, &br)
		out.BytesIn += br.BytesIn
		out.BytesOut += br.BytesOut
		if len(br.Continue) == 0 || string(br.Continue) == "null" {
			out.Status = RunSucceeded
			return out, nil
		}
		cursor = br.Continue
		out.Log += fmt.Sprintf("batch %d done, continuing\n", attempt)
	}
}
