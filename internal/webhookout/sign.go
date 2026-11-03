package webhookout

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Signature returns "sha256=" + hex(HMAC-SHA256(secret, ts + "." + body)).
func Signature(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Tolerance is how far the timestamp of a delivery may be from the receiver clock.
const Tolerance = 300 * time.Second

// Verify is the reference receiver check: it accepts if the timestamp is within Tolerance of
// now and ANY of the signatures matches the body for ANY of the secrets (current and, during a
// rotation, previous). Comparison is constant time.
func Verify(secrets []string, tsHeader string, sigHeaders []string, body []byte, now time.Time) bool {
	ts, err := strconv.ParseInt(strings.TrimSpace(tsHeader), 10, 64)
	if err != nil {
		return false
	}
	d := now.Sub(time.Unix(ts, 0))
	if d < 0 {
		d = -d
	}
	if d > Tolerance {
		return false
	}
	ok := false
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		want := Signature(secret, ts, body)
		for _, got := range sigHeaders {
			// no early exit: every candidate is compared
			if hmac.Equal([]byte(strings.TrimSpace(got)), []byte(want)) {
				ok = true
			}
		}
	}
	return ok
}
