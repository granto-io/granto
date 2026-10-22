package oidc_test

import (
	"testing"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/oidc"
)

func TestDiscoveryFrontBackChannelFlags(t *testing.T) {
	t.Parallel()
	d := oidc.NewDiscovery(&config.Config{
		Token: config.TokenConfig{Issuer: "https://auth.example/"},
	})
	doc := d.Document()
	if !doc.FrontChannelLogoutSupported || !doc.FrontChannelLogoutSessionSupported {
		t.Fatalf("front-channel flags: %+v", doc)
	}
	if !doc.BackChannelLogoutSupported || !doc.BackChannelLogoutSessionSupported {
		t.Fatalf("back-channel flags: %+v", doc)
	}
	if doc.EndSessionEndpoint != "https://auth.example/oauth2/logout" {
		t.Fatalf("EndSessionEndpoint = %q", doc.EndSessionEndpoint)
	}
}
