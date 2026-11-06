package objstore

import (
	"bytes"
	"strings"
	"testing"
)

func TestArchiveRestore(t *testing.T) {
	st, _ := Open(t.TempDir())
	for _, b := range []string{"proj-a", "proj-b"} {
		if err := st.CreateBucket(b); err != nil {
			t.Fatal(err)
		}
	}
	put := func(b, k, v string) {
		if _, err := st.Put(b, k, strings.NewReader(v), writeOpts{MaxBytes: -1}); err != nil {
			t.Fatal(err)
		}
	}
	put("proj-a", "one", "111")
	put("proj-a", "dir/two", "22")
	put("proj-b", "other", "x")
	var buf bytes.Buffer
	if err := st.Archive([]string{"proj-a"}, &buf); err != nil {
		t.Fatal(err)
	}
	// damage the live data, then restore
	put("proj-a", "one", "CHANGED")
	put("proj-a", "extra", "zzz")
	if _, err := st.Restore(bytes.NewReader(buf.Bytes()), func(b string) bool { return b == "proj-a" }); err != nil {
		t.Fatal(err)
	}
	if o, _ := st.Stat("proj-a", "one"); o.Size != 3 {
		t.Fatalf("not restored: %+v", o)
	}
	if _, err := st.Stat("proj-a", "extra"); err == nil {
		t.Fatal("object created after the backup survived the restore")
	}
	if st.Usage("proj-a") != 5 || st.Usage("proj-b") != 1 {
		t.Fatalf("usage a=%d b=%d", st.Usage("proj-a"), st.Usage("proj-b"))
	}
	// buckets outside the allow list are refused and nothing changes
	if _, err := st.Restore(bytes.NewReader(buf.Bytes()), func(string) bool { return false }); err == nil {
		t.Fatal("restore into a foreign bucket accepted")
	}
	if st.Usage("proj-a") != 5 {
		t.Fatal("refused restore modified data")
	}
}
