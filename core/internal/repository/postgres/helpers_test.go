package postgres

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/granto-io/granto/core/internal/domain"
)

func TestIntervalDurationRoundTrip(t *testing.T) {
	t.Parallel()

	if intervalToDuration(pgtype.Interval{}) != nil {
		t.Fatal("invalid interval")
	}
	if durationToInterval(nil).Valid {
		t.Fatal("nil duration")
	}

	d := 90 * time.Second
	iv := durationToInterval(&d)
	if !iv.Valid || iv.Microseconds != d.Microseconds() {
		t.Fatalf("interval: %#v", iv)
	}
	back := intervalToDuration(iv)
	if back == nil || *back != d {
		t.Fatalf("back: %v", back)
	}

	got := intervalToDuration(pgtype.Interval{Days: 1, Valid: true})
	if got == nil || *got != 24*time.Hour {
		t.Fatalf("days: %v", got)
	}
	got = intervalToDuration(pgtype.Interval{Months: 1, Valid: true})
	if got == nil || *got != 30*24*time.Hour {
		t.Fatalf("months: %v", got)
	}
}

func TestNullableStr(t *testing.T) {
	t.Parallel()
	if nullableStr("") != nil {
		t.Fatal("empty")
	}
	p := nullableStr("x")
	if p == nil || *p != "x" {
		t.Fatalf("%v", p)
	}
}

func TestJSONMapHelpers(t *testing.T) {
	t.Parallel()

	b, err := marshalJSONMap(nil)
	if err != nil || string(b) != "{}" {
		t.Fatalf("nil map: %s %v", b, err)
	}
	b, err = marshalJSONMap(map[string]any{"a": 1})
	if err != nil || string(b) != `{"a":1}` {
		t.Fatalf("map: %s %v", b, err)
	}

	b, err = marshalJSONMapNullable(nil)
	if err != nil || b != nil {
		t.Fatalf("nullable nil: %v %v", b, err)
	}
	b, err = marshalJSONMapNullable(map[string]any{"k": "v"})
	if err != nil || string(b) != `{"k":"v"}` {
		t.Fatalf("nullable map: %s %v", b, err)
	}

	m, err := unmarshalJSONMap(nil)
	if err != nil || m != nil {
		t.Fatalf("empty raw: %#v %v", m, err)
	}
	m, err = unmarshalJSONMap([]byte(`{"x":"y"}`))
	if err != nil || m["x"] != "y" {
		t.Fatalf("unmarshal: %#v %v", m, err)
	}
	if _, err := unmarshalJSONMap([]byte(`{`)); err == nil {
		t.Fatal("expected invalid json error")
	}
}

func TestGrantTypeHelpers(t *testing.T) {
	t.Parallel()
	ss := []string{"authorization_code", "refresh_token"}
	gs := stringsToGrantTypes(ss)
	if gs[0] != domain.GrantTypeAuthorizationCode {
		t.Fatalf("%#v", gs)
	}
	back := grantTypesToStrings(gs)
	if back[1] != "refresh_token" {
		t.Fatalf("%#v", back)
	}
}
