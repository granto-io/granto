package postgres

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestIntervalDurationRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("invalid interval becomes nil duration", func(t *testing.T) {
		got := intervalToDuration(pgtype.Interval{})
		if got != nil {
			t.Fatalf("intervalToDuration(invalid) = %v, want nil", got)
		}
	})

	t.Run("nil duration becomes invalid interval", func(t *testing.T) {
		got := durationToInterval(nil)
		if got.Valid {
			t.Fatalf("durationToInterval(nil).Valid = true, want false; got %#v", got)
		}
	})

	t.Run("seconds round-trip", func(t *testing.T) {
		d := 90 * time.Second
		iv := durationToInterval(&d)
		if !iv.Valid {
			t.Fatalf("durationToInterval(90s).Valid = false, want true")
		}
		if iv.Microseconds != d.Microseconds() {
			t.Fatalf("durationToInterval(90s).Microseconds = %d, want %d", iv.Microseconds, d.Microseconds())
		}
		back := intervalToDuration(iv)
		if back == nil {
			t.Fatalf("intervalToDuration(...) = nil, want %v", d)
		}
		if *back != d {
			t.Fatalf("intervalToDuration(...) = %v, want %v", *back, d)
		}
	})

	t.Run("one day interval", func(t *testing.T) {
		got := intervalToDuration(pgtype.Interval{Days: 1, Valid: true})
		want := 24 * time.Hour
		if got == nil || *got != want {
			t.Fatalf("intervalToDuration(Days=1) = %v, want %v", got, want)
		}
	})

	t.Run("one month approximates thirty days", func(t *testing.T) {
		got := intervalToDuration(pgtype.Interval{Months: 1, Valid: true})
		want := 30 * 24 * time.Hour
		if got == nil || *got != want {
			t.Fatalf("intervalToDuration(Months=1) = %v, want %v (30d approximation)", got, want)
		}
	})
}

func TestNullableStr(t *testing.T) {
	t.Parallel()

	t.Run("empty string becomes nil", func(t *testing.T) {
		if got := nullableStr(""); got != nil {
			t.Fatalf("nullableStr(%q) = %#v, want nil", "", got)
		}
	})

	t.Run("non-empty returns pointer", func(t *testing.T) {
		got := nullableStr("x")
		if got == nil {
			t.Fatalf("nullableStr(%q) = nil, want pointer to %q", "x", "x")
		}
		if *got != "x" {
			t.Fatalf("nullableStr(%q) = %q, want %q", "x", *got, "x")
		}
	})
}

func TestJSONMapHelpers(t *testing.T) {
	t.Parallel()

	t.Run("marshal nil map as empty object", func(t *testing.T) {
		b, err := marshalJSONMap(nil)
		if err != nil {
			t.Fatalf("marshalJSONMap(nil) unexpected error: %v", err)
		}
		if string(b) != "{}" {
			t.Fatalf("marshalJSONMap(nil) = %q, want %q", b, "{}")
		}
	})

	t.Run("marshal map", func(t *testing.T) {
		b, err := marshalJSONMap(map[string]any{"a": 1})
		if err != nil {
			t.Fatalf("marshalJSONMap unexpected error: %v", err)
		}
		if string(b) != `{"a":1}` {
			t.Fatalf("marshalJSONMap({a:1}) = %q, want %q", b, `{"a":1}`)
		}
	})

	t.Run("marshal nullable nil stays nil bytes", func(t *testing.T) {
		b, err := marshalJSONMapNullable(nil)
		if err != nil {
			t.Fatalf("marshalJSONMapNullable(nil) unexpected error: %v", err)
		}
		if b != nil {
			t.Fatalf("marshalJSONMapNullable(nil) = %q, want nil bytes", b)
		}
	})

	t.Run("marshal nullable map", func(t *testing.T) {
		b, err := marshalJSONMapNullable(map[string]any{"k": "v"})
		if err != nil {
			t.Fatalf("marshalJSONMapNullable unexpected error: %v", err)
		}
		if string(b) != `{"k":"v"}` {
			t.Fatalf("marshalJSONMapNullable = %q, want %q", b, `{"k":"v"}`)
		}
	})

	t.Run("unmarshal empty raw is nil map", func(t *testing.T) {
		m, err := unmarshalJSONMap(nil)
		if err != nil {
			t.Fatalf("unmarshalJSONMap(nil) unexpected error: %v", err)
		}
		if m != nil {
			t.Fatalf("unmarshalJSONMap(nil) = %#v, want nil", m)
		}
	})

	t.Run("unmarshal object", func(t *testing.T) {
		m, err := unmarshalJSONMap([]byte(`{"x":"y"}`))
		if err != nil {
			t.Fatalf("unmarshalJSONMap unexpected error: %v", err)
		}
		if m["x"] != "y" {
			t.Fatalf(`unmarshalJSONMap(...)["x"] = %#v, want %q`, m["x"], "y")
		}
	})

	t.Run("unmarshal invalid json errors", func(t *testing.T) {
		if _, err := unmarshalJSONMap([]byte(`{`)); err == nil {
			t.Fatalf("unmarshalJSONMap(invalid) = nil error, want parse error")
		}
	})
}
