package objstore

import (
	"strings"
	"testing"
)

// Open no lee los indices: un bucket existente se carga en su primer uso y conserva sus objetos.
func TestOpenLoadsBucketsOnFirstUse(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	if err := st.CreateBucket("fotos"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put("fotos", "a.txt", strings.NewReader("hola"), writeOpts{MaxBytes: -1}); err != nil {
		t.Fatal(err)
	}

	re, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(re.b) != 0 || len(re.lazyNames()) != 1 {
		t.Fatalf("Open must not read indexes: loaded=%d lazy=%v", len(re.b), re.lazyNames())
	}
	if !re.HasBucket("fotos") {
		t.Fatal("bucket found at Open must exist")
	}
	if o, err := re.Stat("fotos", "a.txt"); err != nil || o.Size != 4 {
		t.Fatalf("Stat after lazy load: %+v %v", o, err)
	}
	if re.Usage("fotos") != 4 || len(re.lazyNames()) != 0 {
		t.Fatalf("usage=%d lazy=%v", re.Usage("fotos"), re.lazyNames())
	}
}
