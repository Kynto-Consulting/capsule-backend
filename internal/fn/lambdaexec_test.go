package fn

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/google/uuid"
)

type fakeLambda struct {
	created  []*lambda.CreateFunctionInput
	exists   bool
	cfg      []*lambda.UpdateFunctionConfigurationInput
	payloads []InvokePayload
	replies  []string
	fnErr    bool
}

func (f *fakeLambda) CreateFunction(_ context.Context, in *lambda.CreateFunctionInput, _ ...func(*lambda.Options)) (*lambda.CreateFunctionOutput, error) {
	f.created = append(f.created, in)
	return &lambda.CreateFunctionOutput{}, nil
}
func (f *fakeLambda) UpdateFunctionCode(_ context.Context, _ *lambda.UpdateFunctionCodeInput, _ ...func(*lambda.Options)) (*lambda.UpdateFunctionCodeOutput, error) {
	if !f.exists {
		return nil, errors.New("ResourceNotFoundException")
	}
	return &lambda.UpdateFunctionCodeOutput{}, nil
}
func (f *fakeLambda) UpdateFunctionConfiguration(_ context.Context, in *lambda.UpdateFunctionConfigurationInput, _ ...func(*lambda.Options)) (*lambda.UpdateFunctionConfigurationOutput, error) {
	f.cfg = append(f.cfg, in)
	return &lambda.UpdateFunctionConfigurationOutput{}, nil
}
func (f *fakeLambda) Invoke(_ context.Context, in *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	var p InvokePayload
	json.Unmarshal(in.Payload, &p)
	f.payloads = append(f.payloads, p)
	out := &lambda.InvokeOutput{Payload: []byte(f.replies[len(f.payloads)-1])}
	if f.fnErr {
		s := "Unhandled"
		out.FunctionError = &s
	}
	return out, nil
}

func lfn() *Function {
	return &Function{ID: uuid.MustParse("12345678-9abc-def0-1234-56789abcdef0"), Name: "migrar", MemoryMB: 512, TimeoutSeconds: 7200, ProjectID: uuid.New()}
}

func TestLambdaEnsureCapsTimeoutAndNeverPutsSecretsInEnvironment(t *testing.T) {
	api := &fakeLambda{}
	e := &LambdaExecutor{API: api, Account: "123"}
	if err := e.Ensure(context.Background(), lfn(), "123.dkr.ecr/x:1"); err != nil {
		t.Fatal(err)
	}
	c := api.created[0]
	if *c.FunctionName != "capsule-fn-123456789abc" || *c.Timeout != 900 || *c.MemorySize != 512 || c.Environment != nil {
		t.Fatalf("%+v", c)
	}
	if !strings.HasSuffix(*c.Role, ":role/capsule-lambda-role") {
		t.Fatal(*c.Role)
	}
	api.exists = true
	e.Ensure(context.Background(), lfn(), "img")
	if len(api.cfg) != 1 || *api.cfg[0].Timeout != 900 {
		t.Fatal("update must re-apply limits")
	}
}

func TestLambdaBatchesUntilDone(t *testing.T) {
	api := &fakeLambda{replies: []string{`{"continue":{"i":10},"bytes_in":100,"bytes_out":50}`, `{"continue":{"i":20},"bytes_in":100}`, `{"bytes_in":5}`}}
	e := &LambdaExecutor{API: api}
	minted := 0
	out, err := e.Run(context.Background(), lfn(), &Run{ID: uuid.New(), Payload: json.RawMessage(`{"x":1}`)}, time.Now().Add(2*time.Hour),
		func(a int) (map[string]string, error) {
			minted++
			return map[string]string{"CAPSULE_TOKEN": "capfn_t" + string(rune('0'+a))}, nil
		})
	if err != nil || out.Status != RunSucceeded || out.Batches != 3 || out.BytesIn != 205 || out.BytesOut != 50 {
		t.Fatalf("%+v %v", out, err)
	}
	if minted != 3 || api.payloads[1].Env["CAPSULE_TOKEN"] == api.payloads[2].Env["CAPSULE_TOKEN"] {
		t.Fatal("each batch needs its own token")
	}
	if string(api.payloads[1].Cursor) != `{"i":10}` || api.payloads[2].Attempt != 2 || api.payloads[0].BudgetMS != BatchSlice.Milliseconds() {
		t.Fatalf("%+v", api.payloads)
	}
}

func TestLambdaTotalDeadlineAndFunctionError(t *testing.T) {
	api := &fakeLambda{replies: []string{`{"continue":1}`}}
	clock := time.Now()
	e := &LambdaExecutor{API: api, Now: func() time.Time { c := clock; clock = clock.Add(14 * time.Minute); return c }}
	out, _ := e.Run(context.Background(), lfn(), &Run{ID: uuid.New()}, clock.Add(10*time.Minute), func(int) (map[string]string, error) { return nil, nil })
	if out.Status != RunTimeout {
		t.Fatalf("%+v", out)
	}
	api2 := &fakeLambda{replies: []string{`{"errorMessage":"boom"}`}, fnErr: true}
	out, _ = (&LambdaExecutor{API: api2}).Run(context.Background(), lfn(), &Run{ID: uuid.New()}, time.Now().Add(time.Hour), func(int) (map[string]string, error) { return nil, nil })
	if out.Status != RunFailed || !strings.Contains(out.Log, "boom") {
		t.Fatalf("%+v", out)
	}
}
