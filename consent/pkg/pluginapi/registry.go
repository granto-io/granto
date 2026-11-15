package pluginapi

import (
	"fmt"
	"sort"
	"sync"
)

// Factory creates a fresh plugin instance.
type Factory func() Plugin

// Registry maps plugin names to factories.
//
// Plugins register in init() (like database/sql drivers); the process
// selects a subset at runtime via plugins.enabled.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Register adds a plugin factory. It panics on an empty name or duplicate,
// which can only be a programming error in init().
func (r *Registry) Register(name string, factory Factory) {
	if name == "" {
		panic("pluginapi: register with empty name")
	}
	if factory == nil {
		panic(fmt.Sprintf("pluginapi: nil factory for %q", name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; exists {
		panic(fmt.Sprintf("pluginapi: plugin %q registered twice", name))
	}
	r.factories[name] = factory
}

// New instantiates a plugin by name.
func (r *Registry) New(name string) (Plugin, bool) {
	r.mu.RLock()
	factory, ok := r.factories[name]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return factory(), true
}

// Names returns registered names in sorted order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var defaultRegistry = NewRegistry()

// Register adds a plugin to the process-wide registry from init().
func Register(name string, factory Factory) {
	defaultRegistry.Register(name, factory)
}

// Default returns the process-wide registry used by pkg/server.
func Default() *Registry {
	return defaultRegistry
}
