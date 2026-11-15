package pluginapi

import "testing"

type testPlugin struct{ name string }

func (p *testPlugin) Name() string        { return p.name }
func (p *testPlugin) DisplayName() string { return p.name }
func (p *testPlugin) Kind() Kind          { return FormKind }
func (p *testPlugin) Init(Host) error     { return nil }

func TestRegistry_RegisterAndNew(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register("b", func() Plugin { return &testPlugin{name: "b"} })
	r.Register("a", func() Plugin { return &testPlugin{name: "a"} })

	if got := r.Names(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Names() = %v, want [a b]", got)
	}
	p, ok := r.New("a")
	if !ok || p.Name() != "a" {
		t.Fatalf("New(a) = %v, %v", p, ok)
	}
	if _, ok := r.New("missing"); ok {
		t.Fatal("New(missing) should not exist")
	}
}

func TestRegistry_DuplicatePanics(t *testing.T) {
	t.Parallel()

	r := NewRegistry()
	r.Register("a", func() Plugin { return &testPlugin{name: "a"} })

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r.Register("a", func() Plugin { return &testPlugin{name: "a"} })
}
