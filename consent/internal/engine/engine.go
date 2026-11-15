// Package engine orchestrates the consent service: it validates login and
// consent challenges against core, enforces challenge-bound CSRF, mounts
// plugin routes, and renders the consent page.
package engine

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/granto-io/granto/consent/internal/adminclient"
	"github.com/granto-io/granto/consent/internal/csrf"
	"github.com/granto-io/granto/consent/pkg/pluginapi"
)

// Options configures the engine.
type Options struct {
	Logger *slog.Logger
	Admin  adminclient.Client
	CSRF   *csrf.Service

	// Identity is the identity backend client exposed to plugins via
	// Host.Identity. May be nil when no identity service is configured;
	// plugins that need it must fail Init in that case.
	Identity pluginapi.IdentityClient

	// Plugins is the registry populated by plugin init() functions.
	Plugins *pluginapi.Registry
	// Enabled lists active plugin names, in display order.
	Enabled []string
	// PluginConfig carries plugins.config.<name> nodes.
	PluginConfig map[string]yaml.Node
}

// Engine is the consent service orchestrator.
type Engine struct {
	logger   *slog.Logger
	admin    adminclient.Client
	csrf     *csrf.Service
	identity pluginapi.IdentityClient
	plugins  *pluginapi.Registry
	enabled  []string
	config   map[string]yaml.Node
	choices  []pluginChoice
}

type pluginChoice struct {
	Name        string
	DisplayName string
}

// New validates the configuration and prepares the engine.
func New(opts Options) (*Engine, error) {
	if opts.Admin == nil {
		return nil, fmt.Errorf("engine: admin client is required")
	}
	if opts.CSRF == nil {
		return nil, fmt.Errorf("engine: csrf service is required")
	}
	if opts.Plugins == nil {
		return nil, fmt.Errorf("engine: plugin registry is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{
		logger:   logger,
		admin:    opts.Admin,
		csrf:     opts.CSRF,
		identity: opts.Identity,
		plugins:  opts.Plugins,
		config:   opts.PluginConfig,
	}

	seen := make(map[string]struct{}, len(opts.Enabled))
	for _, name := range opts.Enabled {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("engine: plugin %q enabled twice", name)
		}
		seen[name] = struct{}{}

		plugin, ok := opts.Plugins.New(name)
		if !ok {
			return nil, fmt.Errorf("engine: plugin %q is enabled but not registered", name)
		}
		if plugin.Name() != name {
			return nil, fmt.Errorf("engine: plugin registered as %q reports name %q", name, plugin.Name())
		}
		e.enabled = append(e.enabled, name)
		e.choices = append(e.choices, pluginChoice{Name: name, DisplayName: plugin.DisplayName()})
	}
	if len(e.enabled) == 0 {
		return nil, fmt.Errorf("engine: at least one plugin must be enabled")
	}
	return e, nil
}

// RegisterRoutes mounts the engine HTTP routes and every enabled plugin.
// Plugin routes live under /login/<plugin-name>.
func (e *Engine) RegisterRoutes(r chi.Router) error {
	r.Get("/login", e.handleLogin)
	r.Get("/consent", e.handleConsentGet)
	r.Post("/consent", e.handleConsentPost)

	for _, name := range e.enabled {
		plugin, ok := e.plugins.New(name)
		if !ok {
			return fmt.Errorf("engine: plugin %q is enabled but not registered", name)
		}
		router := chi.NewRouter()
		host := &host{
			engine: e,
			router: router,
			config: e.pluginConfig(name),
			logger: e.logger.With("plugin", name),
		}
		if err := plugin.Init(host); err != nil {
			return fmt.Errorf("engine: init plugin %q: %w", name, err)
		}
		r.Mount("/login/"+name, router)
	}
	return nil
}

func (e *Engine) pluginConfig(name string) *yaml.Node {
	if node, ok := e.config[name]; ok {
		return &node
	}
	return &yaml.Node{Kind: yaml.MappingNode}
}
