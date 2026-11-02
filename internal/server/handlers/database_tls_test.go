package handlers

import (
	"reflect"
	"testing"
)

func TestPostgresTLSArgs(t *testing.T) {
	mount, cmd := postgresTLSArgs("postgres", "/opt/capsule/certs")
	if !reflect.DeepEqual(mount, []string{"-v", "/opt/capsule/certs:/certs:ro"}) {
		t.Fatalf("mount = %v", mount)
	}
	want := []string{"-c", "ssl=on", "-c", "ssl_cert_file=/certs/server.crt", "-c", "ssl_key_file=/certs/server.key"}
	if !reflect.DeepEqual(cmd, want) {
		t.Fatalf("cmd = %v", cmd)
	}
	if m, c := postgresTLSArgs("postgres", ""); m != nil || c != nil {
		t.Fatal("no TLS dir must add no flags")
	}
	if m, c := postgresTLSArgs("mysql", "/x"); m != nil || c != nil {
		t.Fatal("TLS flags are postgres only")
	}
}

func TestPostgresSSLQuery(t *testing.T) {
	if postgresSSLQuery("") != "" || postgresSSLQuery("/c") != "?sslmode=require" {
		t.Fatal("unexpected ssl query")
	}
}

func TestDBPortRange(t *testing.T) {
	cases := []struct {
		in       string
		from, to int
	}{
		{"", 0, 0}, {"40000-40199", 40000, 40199}, {"x", 0, 0}, {"500-600", 0, 0}, {"40100-40000", 0, 0}, {"40000-70000", 0, 0},
	}
	for _, c := range cases {
		t.Setenv("CAPSULE_DB_PORT_RANGE", c.in)
		if f, to := dbPortRange(); f != c.from || to != c.to {
			t.Errorf("%q => %d-%d, want %d-%d", c.in, f, to, c.from, c.to)
		}
	}
}
