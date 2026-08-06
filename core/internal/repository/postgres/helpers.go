package postgres

import (
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/granto-io/granto/core/internal/domain"
)

func intervalToDuration(iv pgtype.Interval) *time.Duration {
	if !iv.Valid {
		return nil
	}
	d := time.Duration(iv.Microseconds)*time.Microsecond +
		time.Duration(iv.Days)*24*time.Hour +
		time.Duration(iv.Months)*30*24*time.Hour
	return &d
}

func durationToInterval(d *time.Duration) pgtype.Interval {
	if d == nil {
		return pgtype.Interval{}
	}
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}

func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func stringsToGrantTypes(ss []string) []domain.GrantType {
	out := make([]domain.GrantType, len(ss))
	for i, s := range ss {
		out[i] = domain.GrantType(s)
	}
	return out
}

func grantTypesToStrings(gs []domain.GrantType) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = string(g)
	}
	return out
}

func marshalJSONMap(m map[string]any) ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

func marshalJSONMapNullable(m map[string]any) ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

func unmarshalJSONMap(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
