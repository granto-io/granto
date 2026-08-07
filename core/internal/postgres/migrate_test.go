package postgres

import "testing"

func TestToPgx5DSN(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"postgres://user:pass@localhost/db", "pgx5://user:pass@localhost/db"},
		{"postgresql://user@localhost/db", "pgx5://user@localhost/db"},
		{"pgx5://already", "pgx5://already"},
		{"postgres://a/postgres://b", "pgx5://a/postgres://b"},
	}
	for _, tc := range cases {
		if got := toPgx5DSN(tc.in); got != tc.want {
			t.Fatalf("toPgx5DSN(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}
