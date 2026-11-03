package environments

import (
	"fmt"
	"strings"
	"time"
	_ "time/tzdata" // zone database embedded: windows must work on hosts without /usr/share/zoneinfo
)

var weekdayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

func parseHM(s string) (h, m int, err error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, fmt.Errorf("use HH:MM")
	}
	if _, err = fmt.Sscanf(s, "%02d:%02d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("use HH:MM")
	}
	return h, m, nil
}

// ValidateWindow reports why w is unusable ("" = ok).
func ValidateWindow(w Window) string {
	if _, err := time.LoadLocation(w.TZ); err != nil || w.TZ == "" {
		return "tz must be an IANA zone such as America/Lima"
	}
	fh, fm, err := parseHM(w.From)
	if err != nil {
		return "from: " + err.Error()
	}
	th, tm, err := parseHM(w.To)
	if err != nil {
		return "to: " + err.Error()
	}
	if fh == th && fm == tm {
		return "from and to cannot be equal (omit the window for all day)"
	}
	for _, d := range w.Days {
		if _, ok := weekdayNames[strings.ToLower(d)]; !ok {
			return "days must be mon..sun"
		}
	}
	return ""
}

// span returns the [start,end) instants of window w that STARTS on the local calendar day of ref
// (a window with to <= from crosses midnight and ends the next day). ok is false when the window
// does not run that weekday.
func span(w Window, ref time.Time) (start, end time.Time, ok bool) {
	loc, err := time.LoadLocation(w.TZ)
	if err != nil {
		return
	}
	day := ref.In(loc)
	if len(w.Days) > 0 {
		match := false
		for _, d := range w.Days {
			if weekdayNames[strings.ToLower(d)] == day.Weekday() {
				match = true
			}
		}
		if !match {
			return
		}
	}
	fh, fm, _ := parseHM(w.From)
	th, tm, _ := parseHM(w.To)
	y, mo, d := day.Date()
	start = time.Date(y, mo, d, fh, fm, 0, 0, loc)
	endDay := d
	if th*60+tm <= fh*60+fm {
		endDay = d + 1
	}
	end = time.Date(y, mo, endDay, th, tm, 0, 0, loc)
	return start, end, true
}

// WindowOpen reports whether t falls inside any window (no windows = always open) and, when open,
// the instant the current window closes.
func WindowOpen(ws []Window, t time.Time) (bool, time.Time) {
	if len(ws) == 0 {
		return true, time.Time{}
	}
	for _, w := range ws {
		for back := 0; back <= 1; back++ { // window started today or yesterday (midnight crossing)
			s, e, ok := span(w, t.AddDate(0, 0, -back))
			if ok && !t.Before(s) && t.Before(e) {
				return true, e
			}
		}
	}
	return false, time.Time{}
}

// OpenAtOrAfter returns t when a window is open at t, else the start of the next window.
func OpenAtOrAfter(ws []Window, t time.Time) time.Time {
	if open, _ := WindowOpen(ws, t); open {
		return t
	}
	var best time.Time
	for _, w := range ws {
		for fwd := 0; fwd <= 8; fwd++ {
			s, _, ok := span(w, t.AddDate(0, 0, fwd))
			if ok && s.After(t) && (best.IsZero() || s.Before(best)) {
				best = s
				break
			}
		}
	}
	if best.IsZero() {
		return t.Add(24 * time.Hour)
	}
	return best
}
