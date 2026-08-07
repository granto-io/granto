package postgres

import "testing"

func TestToPgx5DSN(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in, want string
	}{
		{name: "postgres scheme", in: "postgres://user:pass@localhost/db", want: "pgx5://user:pass@localhost/db"},
		{name: "postgresql scheme", in: "postgresql://user@localhost/db", want: "pgx5://user@localhost/db"},
		{name: "already pgx5", in: "pgx5://already", want: "pgx5://already"},
		{name: "only first postgres scheme replaced", in: "postgres://a/postgres://b", want: "pgx5://a/postgres://b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toPgx5DSN(tc.in)
			if got != tc.want {
				t.Fatalf("toPgx5DSN(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
