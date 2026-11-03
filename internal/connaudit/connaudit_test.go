package connaudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testClassifier() *Classifier {
	return &Classifier{
		DirectHosts: []string{"db.tumi-ai.com"}, DirectIPs: []string{"3.4.5.6"},
		GatewayDomains: []string{"db.tumi-ai.com", "apps.tumi-ai.com"},
		OwnShort:       "abcdef123456",
	}
}

func TestClassifyTable(t *testing.T) {
	c := testClassifier()
	cases := []struct {
		host string
		port int
		kind Kind
		sev  Severity
	}{
		{"db.tumi-ai.com", 40010, KindDirectPort, SevWarning},
		{"db.tumi-ai.com", 443, KindOK, SevInfo},
		{"x1.db.tumi-ai.com", 5432, KindOK, SevInfo},
		{"*.db.tumi-ai.com", 5432, KindOK, SevInfo},
		{"foo.apps.tumi-ai.com", 443, KindOK, SevInfo},
		{"3.4.5.6", 41001, KindDirectPort, SevWarning},
		{"localhost", 40100, KindDirectPort, SevWarning},
		{"127.0.0.1", 5432, KindLoopback, SevWarning},
		{"::1", 5432, KindLoopback, SevWarning},
		{"[::1]", 6379, KindLoopback, SevWarning},
		{"::ffff:127.0.0.1", 80, KindLoopback, SevWarning},
		{"0.0.0.0", 3000, KindOK, SevInfo},
		{"172.17.0.2", 5432, KindDockerBridge, SevWarning},
		{"host.docker.internal", 5432, KindDockerBridge, SevWarning},
		{"gateway.docker.internal", 0, KindDockerBridge, SevWarning},
		{"capsule-app-abcdef123456", 3000, KindContainer, SevWarning},
		{"capsule-app-111111111111", 3000, KindContainer, SevCritical},
		{"capsule-db-9f", 5432, KindContainer, SevCritical},
		{"capsule-redis", 6379, KindContainer, SevCritical},
		{"capsule-backend", 8080, KindContainer, SevCritical},
		{"10.0.3.4", 5432, KindPrivate, SevInfo},
		{"192.168.1.5", 80, KindPrivate, SevInfo},
		{"100.64.1.1", 80, KindPrivate, SevInfo},
		{"169.254.10.10", 80, KindPrivate, SevInfo},
		{"fd12:3456::1", 5432, KindPrivate, SevInfo},
		{"fe80::1%eth0", 5432, KindPrivate, SevInfo},
		{"ip-10-0-0-1.ec2.internal", 80, KindPrivate, SevInfo},
		{"169.254.169.254", 80, KindMetadata, SevCritical},
		{"fd00:ec2::254", 80, KindMetadata, SevCritical},
		{"2001:db8::1", 5432, KindOK, SevInfo},
		{"example.com", 443, KindOK, SevInfo},
		{"${DB_HOST}", 5432, KindOK, SevInfo},
	}
	for _, tc := range cases {
		k, s := c.Classify(tc.host, tc.port)
		if k != tc.kind || s != tc.sev {
			t.Errorf("%s:%d = %s/%s, want %s/%s", tc.host, tc.port, k, s, tc.kind, tc.sev)
		}
	}
}

func TestEnvURLsAndSecrets(t *testing.T) {
	c := testClassifier()
	env := map[string]string{
		"DATABASE_URL": "postgres://admin:S3cr3tPass@db.tumi-ai.com:40012/app?sslmode=require",
		"REDIS_URL":    "redis://:topsecret@[::1]:6379/0",
		"PG6":          "postgres://u:hunter2@[2001:db8::1]:5432/db",
		"PRIV6":        "postgres://u:hunter3@[fd00::5]:5432/db",
		"META":         "http://169.254.169.254/latest/meta-data",
		"DB_HOST":      "localhost",
		"DB_PORT":      "40050",
		"CACHE_ADDR":   "capsule-redis:6379",
		"JDBC":         "jdbc:postgresql://172.20.0.3:5432/x?password=jdbcsecret",
		"PUBLIC":       "https://api.example.com/x",
		"PORT":         "3000",
		"HOST":         "127.0.0.1",
		"GW":           "postgres://u:p4ss@abc.db.tumi-ai.com:5432/d",
	}
	fs := AnalyzeEnv(env, c)
	got := map[string]Finding{}
	for _, f := range fs {
		got[f.Source] = f
	}
	want := map[string]Kind{
		"env:DATABASE_URL": KindDirectPort, "env:REDIS_URL": KindLoopback, "env:PRIV6": KindPrivate,
		"env:META": KindMetadata, "env:DB_HOST": KindDirectPort, "env:CACHE_ADDR": KindContainer, "env:JDBC": KindDockerBridge,
	}
	for src, k := range want {
		if got[src].Kind != k {
			t.Errorf("%s: kind %q want %q (%v)", src, got[src].Kind, k, fs)
		}
	}
	for _, src := range []string{"env:PG6", "env:PUBLIC", "env:PORT", "env:HOST", "env:GW"} {
		if _, ok := got[src]; ok {
			t.Errorf("%s must not be a finding", src)
		}
	}
	if e := got["env:DATABASE_URL"].Endpoint; e != "postgres://***@db.tumi-ai.com:40012" {
		t.Errorf("endpoint %q", e)
	}
	if e := got["env:REDIS_URL"].Endpoint; e != "redis://***@[::1]:6379" {
		t.Errorf("endpoint %q", e)
	}
	raw, _ := json.Marshal(fs)
	for _, secret := range []string{"S3cr3tPass", "topsecret", "hunter2", "hunter3", "jdbcsecret", "sslmode", "p4ss"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret %q leaked: %s", secret, raw)
		}
	}
}

func TestURLShapes(t *testing.T) {
	cases := map[string]string{
		"redis://localhost":                    "redis://localhost:6379",
		"mongodb://u:p@*.db.tumi-ai.com/x":     "mongodb://***@*.db.tumi-ai.com:27017",
		"tcp://10.0.0.1:9000":                  "tcp://10.0.0.1:9000",
		"postgres://u:p@[::1]:5432/db":         "postgres://***@[::1]:5432",
		"amqp://guest:guest@capsule-redis/%2f": "amqp://***@capsule-redis:5672",
	}
	for in, want := range cases {
		eps := ExtractURLs(in)
		if len(eps) != 1 || eps[0].String() != want {
			t.Errorf("%s -> %v, want %s", in, eps, want)
		}
	}
	if len(ExtractURLs("postgres://u:p@${DB_HOST}:5432/x")) != 0 {
		t.Error("placeholder host must be dropped")
	}
}

func TestStableIDIgnoresLine(t *testing.T) {
	c := testClassifier()
	a, _ := newFinding(c, Endpoint{Host: "127.0.0.1", Port: 5432}, "file:src/db.ts:10")
	b, _ := newFinding(c, Endpoint{Host: "127.0.0.1", Port: 5432}, "file:src/db.ts:99")
	d, _ := newFinding(c, Endpoint{Host: "127.0.0.1", Port: 5433}, "file:src/db.ts:10")
	if a.ID != b.ID || a.ID == d.ID || a.ID == "" {
		t.Fatalf("ids %s %s %s", a.ID, b.ID, d.ID)
	}
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanDir(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".env", "DATABASE_URL=postgres://u:envsecret@db.tumi-ai.com:40001/x\nDB_HOST=127.0.0.1\nDB_PORT=5432\n")
	write(t, root, "src/app.ts", "const u = 'redis://:tssecret@capsule-redis:6379';\n// redis://localhost:6379 in a comment\n")
	write(t, root, "config/app.yml", "database:\n  db_host: 10.1.2.3\n  db_port: 5432\n")
	write(t, root, "node_modules/x/index.js", "postgres://localhost:5432")
	write(t, root, "ignored/a.js", "postgres://localhost:5432")
	write(t, root, ".gitignore", "ignored/\n")
	write(t, root, "a..b.env", "REDIS_URL=redis://169.254.169.254:1\n")
	write(t, root, "bin.json", "postgres://localhost:5432\x00\x00")
	write(t, root, "src/app.test.ts", "postgres://localhost:5432")
	write(t, root, ".env.example", "DATABASE_URL=postgres://localhost:5432/x")
	fs, st := ScanDir(context.Background(), root, testClassifier(), ScanLimits{})
	kinds := map[string]Kind{}
	for _, f := range fs {
		kinds[strings.SplitN(f.Source, ":", 3)[1]] = f.Kind
	}
	if kinds[".env"] != KindLoopback && kinds[".env"] != KindDirectPort {
		t.Errorf(".env: %v", fs)
	}
	if kinds["src/app.ts"] != KindContainer || kinds["config/app.yml"] != KindPrivate || kinds["a..b.env"] != KindMetadata {
		t.Errorf("kinds %v", kinds)
	}
	for src := range kinds {
		if strings.Contains(src, "node_modules") || strings.Contains(src, "ignored") || src == "bin.json" || strings.Contains(src, ".test.") || src == ".env.example" {
			t.Errorf("must be skipped: %s", src)
		}
	}
	raw, _ := json.Marshal(fs)
	if strings.Contains(string(raw), "envsecret") || strings.Contains(string(raw), "tssecret") {
		t.Fatal("secret leaked")
	}
	if st.Files == 0 {
		t.Fatal("no files read")
	}
}

func TestScanLimitsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 50; i++ {
		write(t, root, "d/f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".json", `{"u":"redis://127.0.0.1:`+string(rune('1'+i%9))+`"}`)
	}
	_, st := ScanDir(context.Background(), root, testClassifier(), ScanLimits{MaxFiles: 5})
	if st.Files > 5 || !st.Truncated {
		t.Errorf("file bomb not bounded: %+v", st)
	}
	big := strings.Repeat("a", 300<<10) + "postgres://127.0.0.1:5432"
	write(t, root, "big/huge.json", big)
	fs, _ := ScanDir(context.Background(), filepath.Join(root, "big"), testClassifier(), ScanLimits{})
	if len(fs) != 0 {
		t.Error("oversize file must be skipped")
	}
	deep := "x/y/z/w/v/u"
	write(t, root, "deep/"+deep+"/a.json", "redis://127.0.0.1:1")
	fs, _ = ScanDir(context.Background(), filepath.Join(root, "deep"), testClassifier(), ScanLimits{MaxDepth: 3})
	if len(fs) != 0 {
		t.Error("depth limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, st := ScanDir(ctx, root, testClassifier(), ScanLimits{}); !st.Truncated {
		t.Error("cancelled context must stop the scan")
	}
	// symlink to a file outside the tree is never read
	outside := t.TempDir()
	write(t, outside, "secret.json", "redis://127.0.0.1:6379")
	sroot := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "secret.json"), filepath.Join(sroot, "link.json")); err != nil {
		t.Skip("symlinks unavailable: " + err.Error())
	}
	if err := os.Symlink(outside, filepath.Join(sroot, "dirlink")); err != nil {
		t.Skip(err.Error())
	}
	if fs, _ := ScanDir(context.Background(), sroot, testClassifier(), ScanLimits{}); len(fs) != 0 {
		t.Errorf("symlink followed: %v", fs)
	}
}

func TestPolicy(t *testing.T) {
	now := time.Now()
	crit := Finding{ID: "aaaaaaaaaaaa", Severity: SevCritical}
	warn := Finding{ID: "bbbbbbbbbbbb", Severity: SevWarning}
	fs := []Finding{crit, warn}
	if len(Blocking(fs, ModeWarn)) != 0 || len(Blocking(fs, ModeOff)) != 0 || len(Blocking(fs, ModeStrict)) != 1 {
		t.Fatal("strict vs warn")
	}
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	exp := Apply(fs, []Suppression{{FindingID: crit.ID, ExpiresAt: &past}}, now)
	if exp[0].Suppressed || len(Blocking(exp, ModeStrict)) != 1 {
		t.Fatal("expired suppression must not apply")
	}
	act := Apply(fs, []Suppression{{FindingID: crit.ID, ExpiresAt: &future}, {FindingID: warn.ID}}, now)
	if !act[0].Suppressed || !act[1].Suppressed || len(Blocking(act, ModeStrict)) != 0 {
		t.Fatal("active suppression must apply")
	}
	if c := Count(act); c.Suppressed != 2 || c.Critical != 0 {
		t.Fatalf("%+v", c)
	}
	if m, ok := ParseMode(""); !ok || m != ModeWarn {
		t.Fatal("default mode")
	}
	if _, ok := ParseMode("loud"); ok {
		t.Fatal("bad mode accepted")
	}
	if (Suppression{FindingID: "aaaaaaaaaaaa", Reason: "x"}).Validate(now) == "" {
		t.Fatal("short reason accepted")
	}
	if (Suppression{FindingID: "aaaaaaaaaaaa", Reason: "servicio propio dentro del contenedor", ExpiresAt: &past}).Validate(now) == "" {
		t.Fatal("past expiry accepted")
	}
	if msg := (Suppression{FindingID: "aaaaaaaaaaaa", Reason: "servicio propio dentro del contenedor"}).Validate(now); msg != "" {
		t.Fatal(msg)
	}
}

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0
   1: 0200A8C0:A1B2 0100007F:1538 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0
   2: 0200A8C0:0BB8 0900A8C0:D000 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0
   3: garbage
`

const procTCP6 = `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:A1B2 00000000000000000000000001000000:1538 01 00000000:00000000 00:00000000 00000000     0        0 4 1 0
   1: 0000000000000000FFFF00000100007F:A1B3 0000000000000000FFFF00000200A8C0:0050 01 00000000:00000000 00:00000000 00000000 0 0 5 1 0
   2: B80D0120000000000000000001000000:A1B4 B80D0120000000000000000005000000:1538 01 00000000:00000000 00:00000000 00000000 0 0 6 1 0
`

func TestParseProcNet(t *testing.T) {
	v4 := ParseProcNet(strings.NewReader(procTCP), false)
	if len(v4) != 3 {
		t.Fatalf("v4 %v", v4)
	}
	if v4[1].Remote.String() != "127.0.0.1" || v4[1].RemotePort != 5432 || v4[1].Local.String() != "192.168.0.2" {
		t.Errorf("v4[1] %+v", v4[1])
	}
	out := Outbound(v4)
	if len(out) != 1 || out[0].RemotePort != 5432 { // the 3000 one is inbound (listening port)
		t.Errorf("outbound %+v", out)
	}
	v6 := ParseProcNet(strings.NewReader(procTCP6), true)
	if len(v6) != 3 {
		t.Fatalf("v6 %v", v6)
	}
	if v6[0].Remote.String() != "::1" || v6[0].RemotePort != 5432 {
		t.Errorf("v6[0] %+v", v6[0])
	}
	if v6[1].Remote.String() != "192.168.0.2" { // v4-mapped
		t.Errorf("v6[1] %+v", v6[1])
	}
	if v6[2].Remote.String() != "2001:db8::5" {
		t.Errorf("v6[2] %+v", v6[2])
	}
}

func TestObserveAndDegrade(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if args[len(args)-1] == "/proc/net/tcp" {
			return []byte(procTCP), nil
		}
		if args[len(args)-1] == "/proc/net/tcp6" {
			return []byte(procTCP6), nil
		}
		return nil, os.ErrNotExist
	}
	fs, err := Observe(context.Background(), run, nil, "c1", testClassifier())
	if err != nil || len(fs) < 2 {
		t.Fatalf("%v %v", fs, err)
	}
	for _, f := range fs {
		if f.Source != "runtime" {
			t.Errorf("source %s", f.Source)
		}
	}
	none := func(ctx context.Context, name string, args ...string) ([]byte, error) { return nil, os.ErrNotExist }
	if _, err := Observe(context.Background(), none, nil, "c1", nil); err != ErrRuntimeUnavailable {
		t.Fatalf("want degrade, got %v", err)
	}
}
