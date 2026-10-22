package public

import (
	"html/template"
	"net/http"
)

// frontChannelLogoutPage mirrors Hydra's OIDC Front-Channel Logout handoff:
// hidden iframes load each RP's frontchannel_logout_uri, then redirect.
var frontChannelLogoutTmpl = template.Must(template.New("frontchannel_logout").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    {{ if .RedirectTo }}<meta http-equiv="refresh" content="7; URL={{ .RedirectTo }}">{{ end }}
    <title>Logging out</title>
</head>
<style type="text/css">
    iframe { position: absolute; left: 0; top: 0; height: 0; width: 0; border: none; }
</style>
<script>
    var total = {{ len .FrontChannelLogoutURLs }};
    var redir = {{ .RedirectTo }};

	var timeouts = [];
	var redirected = false;
	window.onbeforeunload = () => {
		redirected = true;
		for (var i=0; i<timeouts.length; i++) {
			clearTimeout(timeouts[i]);
		}
		timeouts = [];
	};
	function setAndRegisterTimeout(fct, duration) {
		if (redirected) {
			return;
		}
		timeouts.push(setTimeout(fct, duration));
	}

	function redirect() {
		if (!redir) {
			document.getElementById("done").style.display = "block";
			document.getElementById("redir").style.display = "none";
			return;
		}
		window.location.replace(redir);
		setAndRegisterTimeout(function () {
			window.location.href = redir;
		}, 250);
	}

    function done() {
        total--;
        if (total < 1) {
			setAndRegisterTimeout(redirect, 500);
        }
    }

	setAndRegisterTimeout(redirect, 7000);

	setTimeout(function () {
		document.getElementById("redir").style.display = "block";
	}, 2000);
</script>
<body>
<noscript>
    <p>
        JavaScript is disabled — you should be redirected in a few seconds but if not, click
		{{ if .RedirectTo }}<a href="{{ .RedirectTo }}">here</a>{{ else }}refresh{{ end }} to continue.
    </p>
</noscript>

<p id="redir" style="display: none">
    Redirection takes unusually long.
	{{ if .RedirectTo }}If you are not being redirected, click <a href="{{ .RedirectTo }}">here</a> to continue.{{ end }}
</p>
<p id="done" style="display: none">Logged out</p>

{{ range .FrontChannelLogoutURLs }}<iframe src="{{ . }}" onload="done(this)"></iframe>
{{ end }}
</body>
</html>`))

type frontChannelLogoutView struct {
	RedirectTo             string
	FrontChannelLogoutURLs []string
}

func writeFrontChannelLogoutPage(w http.ResponseWriter, redirectTo string, urls []string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	return frontChannelLogoutTmpl.Execute(w, frontChannelLogoutView{
		RedirectTo:             redirectTo,
		FrontChannelLogoutURLs: urls,
	})
}
