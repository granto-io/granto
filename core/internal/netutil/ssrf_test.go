package netutil_test

import (
	"net"
	"testing"

	"github.com/granto-io/granto/core/internal/netutil"
)

func TestValidateOutboundURL(t *testing.T) {
	t.Parallel()
	ok := []string{
		"https://rp.example/backchannel-logout",
		"https://rp.example:8443/logout",
	}
	for _, u := range ok {
		if err := netutil.ValidateOutboundURL(u); err != nil {
			t.Fatalf("%q: unexpected err %v", u, err)
		}
	}

	bad := []string{
		"",
		"http://rp.example/logout",
		"https://user:pass@rp.example/logout",
		"https://127.0.0.1/logout",
		"https://10.0.0.1/logout",
		"https://192.168.1.1/logout",
		"https://169.254.169.254/latest/meta-data",
		"https://100.64.0.1/logout",
		"https://[::1]/logout",
		"ftp://rp.example/logout",
		"https:///no-host",
	}
	for _, u := range bad {
		if err := netutil.ValidateOutboundURL(u); err == nil {
			t.Fatalf("%q: want error", u)
		}
	}
}

func TestIsBlockedIP(t *testing.T) {
	t.Parallel()
	blocked := []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.1.2", "0.0.0.0"}
	for _, s := range blocked {
		if !netutil.IsBlockedIP(net.ParseIP(s)) {
			t.Fatalf("%s should be blocked", s)
		}
	}
	if netutil.IsBlockedIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("8.8.8.8 should be allowed")
	}
}
