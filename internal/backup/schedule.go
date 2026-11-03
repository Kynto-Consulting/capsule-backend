package backup

import (
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// Schedules accepted by the API.
var scheduleIntervals = map[string]time.Duration{
	"hourly": time.Hour,
	"6h":     6 * time.Hour,
	"12h":    12 * time.Hour,
	"daily":  24 * time.Hour,
	"weekly": 7 * 24 * time.Hour,
}

// ValidSchedule reports whether s is one of hourly|6h|12h|daily|weekly.
func ValidSchedule(s string) bool { _, ok := scheduleIntervals[s]; return ok }

// NextRun is when the next scheduled backup is due: the previous run's start plus the
// interval, or now when the project has never run (failed runs count too, so a broken
// project is retried at its normal cadence rather than every tick).
func NextRun(schedule string, lastStart *time.Time, now time.Time) time.Time {
	iv, ok := scheduleIntervals[schedule]
	if !ok {
		iv = 24 * time.Hour
	}
	if lastStart == nil {
		return now
	}
	return lastStart.Add(iv)
}

var targetNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// ValidTargetName guards the database name used for "restore into a new database".
func ValidTargetName(s string) bool { return targetNameRe.MatchString(s) }

// Key layout: projects/<projectID>/<kind>/<RFC3339>-<runID>.<ext>.enc
func ObjectKey(projectID uuid.UUID, kind string, t time.Time, runID uuid.UUID, ext string) string {
	return fmt.Sprintf("projects/%s/%s/%s-%s.%s.enc", projectID, kind, t.UTC().Format(time.RFC3339), runID, ext)
}

// PlatformKey: platform/<RFC3339>-<runID>.<part>.<ext>.enc
func PlatformKey(t time.Time, runID uuid.UUID, part, ext string) string {
	return fmt.Sprintf("platform/%s-%s.%s.%s.enc", t.UTC().Format(time.RFC3339), runID, part, ext)
}

// ProjectPrefix is the S3 prefix that holds every object of a project.
func ProjectPrefix(projectID uuid.UUID) string { return fmt.Sprintf("projects/%s/", projectID) }
