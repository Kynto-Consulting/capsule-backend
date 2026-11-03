package gitaudit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Page sizes of the JSON listing.
const (
	DefaultLimit = 50
	MaxLimit     = 200
	// ExportPage is the batch size used while streaming a CSV export.
	ExportPage = 1000
	// ExportMaxRows caps one export; when more rows match the export is truncated and the
	// continuation cursor is reported (ExportResult.Next), so a client can ask for the rest.
	ExportMaxRows = 100000
)

// ErrInvalidFilter is wrapped by Filter validation errors.
var ErrInvalidFilter = errors.New("invalid audit filter")

var filterActionRE = regexp.MustCompile(`^[a-z0-9_.]+\*?$`)

// Validate checks f.
func (f Filter) Validate() error {
	if f.Action != "" && (len(f.Action) > 50 || !filterActionRE.MatchString(f.Action)) {
		return fmt.Errorf("%w: action must be a name like git.protection.change or a prefix like git.*", ErrInvalidFilter)
	}
	if len(f.Actor) > 200 {
		return fmt.Errorf("%w: actor is too long", ErrInvalidFilter)
	}
	if f.Since != nil && f.Until != nil && !f.Since.Before(*f.Until) {
		return fmt.Errorf("%w: since must be before until", ErrInvalidFilter)
	}
	return nil
}

// ActorID returns the user id when Actor is one.
func (f Filter) ActorID() (uuid.UUID, bool) {
	id, err := uuid.Parse(f.Actor)
	return id, err == nil
}

// Service is the read side: filtered, cursor-paginated listing and CSV export.
type Service struct{ R Reader }

// NewService builds the service over r.
func NewService(r Reader) *Service { return &Service{R: r} }

func clampLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	if n > MaxLimit {
		return MaxLimit
	}
	return n
}

// ResolveProject turns a project id or slug into the id used by Filter.ProjectID. ok=false when
// the organization has no such project.
func (s *Service) ResolveProject(ctx context.Context, orgID uuid.UUID, ref string) (uuid.UUID, bool, error) {
	return s.R.ProjectID(ctx, orgID, ref)
}

// List returns one page and the cursor of the next ("" when there is no more).
func (s *Service) List(ctx context.Context, orgID uuid.UUID, f Filter, cursor string, limit int) ([]Entry, string, error) {
	if err := f.Validate(); err != nil {
		return nil, "", err
	}
	cur, err := ParseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	limit = clampLimit(limit)
	rows, err := s.R.List(ctx, orgID, f, cur, limit+1)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = Cursor{At: last.CreatedAt, ID: last.ID}.Encode()
	}
	return rows, next, nil
}

// CSVHeader is the first row of an export.
var CSVHeader = []string{
	"id", "created_at", "action", "actor_id", "actor_name", "actor_email", "actor_label", "project_id",
	"resource_type", "resource_id", "ip", "user_agent", "old_values", "new_values", "metadata",
}

// NeutralizeCell makes a value safe to open in a spreadsheet: when the first visible character
// is one that makes Excel, LibreOffice or Sheets evaluate the cell as a formula (= + - @, and
// tab or carriage return which some versions strip first), a single quote is put in front so it
// is read as text. Leading spaces and control characters do not hide the trigger.
func NeutralizeCell(s string) string {
	t := strings.TrimLeftFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\v' || r == '\f' || r == 0xa0 || r == 0xfeff
	})
	if t == "" {
		return s
	}
	switch t[0] {
	case '=', '+', '-', '@':
		return "'" + s
	}
	if s[0] == '\t' || s[0] == '\r' {
		return "'" + s
	}
	return s
}

func jsonCell(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return NeutralizeCell(string(b))
}

func ptrStr(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// CSVRow renders e with every free-text cell neutralized against formula injection.
func CSVRow(e Entry) []string {
	return []string{
		e.ID.String(), e.CreatedAt.UTC().Format(time.RFC3339Nano), NeutralizeCell(e.Action), ptrStr(e.UserID),
		NeutralizeCell(e.ActorName), NeutralizeCell(e.ActorEmail), NeutralizeCell(e.ActorLabel), ptrStr(e.ProjectID),
		NeutralizeCell(e.ResourceType), ptrStr(e.ResourceID), NeutralizeCell(e.IP), NeutralizeCell(e.UserAgent),
		jsonCell(e.OldValues), jsonCell(e.NewValues), jsonCell(e.Metadata),
	}
}

// ExportResult says what an export wrote.
type ExportResult struct {
	Rows      int
	Truncated bool
	Next      string // continuation cursor when Truncated
}

// Export streams the matching entries as CSV (header first), newest first, in batches. It stops
// after max rows (ExportMaxRows when max <= 0) and reports the cursor to continue from.
func (s *Service) Export(ctx context.Context, orgID uuid.UUID, f Filter, cursor string, max int, w io.Writer) (ExportResult, error) {
	var res ExportResult
	if err := f.Validate(); err != nil {
		return res, err
	}
	cur, err := ParseCursor(cursor)
	if err != nil {
		return res, err
	}
	if max <= 0 || max > ExportMaxRows {
		max = ExportMaxRows
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return res, err
	}
	var last *Entry
	for res.Rows < max {
		n := ExportPage
		if left := max - res.Rows; left < n {
			n = left
		}
		// one extra row tells whether more match after the cap
		rows, err := s.R.List(ctx, orgID, f, cur, n+1)
		if err != nil {
			return res, err
		}
		more := len(rows) > n
		if more {
			rows = rows[:n]
		}
		for i := range rows {
			if err := cw.Write(CSVRow(rows[i])); err != nil {
				return res, err
			}
			res.Rows++
			last = &rows[i]
		}
		if len(rows) > 0 {
			cur = &Cursor{At: rows[len(rows)-1].CreatedAt, ID: rows[len(rows)-1].ID}
		}
		if !more {
			cw.Flush()
			return res, cw.Error()
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return res, err
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
	}
	res.Truncated = true
	if last != nil {
		res.Next = Cursor{At: last.CreatedAt, ID: last.ID}.Encode()
	}
	return res, nil
}
