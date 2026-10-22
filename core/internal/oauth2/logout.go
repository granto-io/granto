package oauth2

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
)

// LogoutInput is GET/POST /oauth2/logout (OIDC RP-Initiated Logout).
type LogoutInput struct {
	// SessionIDFromCookie is the granto_sid cookie value (may be empty/invalid).
	SessionIDFromCookie string
	// DeviceIDFromCookie is the granto_did cookie value (may be empty/invalid).
	DeviceIDFromCookie string
	IDTokenHint        string
	ClientID           string
	PostLogoutRedirect string
	State              string
}

// LogoutResult tells the public handler how to finish the browser logout.
type LogoutResult struct {
	ClearCookie bool
	// RedirectTo is empty when the RP did not request (or was not allowed)
	// a post_logout_redirect_uri — handler should respond 200 (or after iframes).
	RedirectTo string
	// FrontChannelLogoutURLs are iframe src URLs for OIDC Front-Channel Logout.
	// When non-empty, the handler serves an HTML page that loads them before redirect.
	FrontChannelLogoutURLs []string
}

// Logout ends AS login session(s) according to session.logout_scope,
// notifies RPs (front/back-channel), and optionally redirects to a registered
// post_logout_redirect_uri.
func (f *Flow) Logout(ctx context.Context, in LogoutInput) (*LogoutResult, error) {
	targets := f.resolveLogoutTargets(ctx, in)

	var frontURLs []string
	var tasks []backChannelTask
	for _, t := range targets {
		urls, tk := f.prepareSessionChannels(ctx, t)
		frontURLs = append(frontURLs, urls...)
		tasks = append(tasks, tk...)
	}
	f.dispatchBackChannelLogout(tasks)

	for _, t := range targets {
		f.deleteOneLoginSession(ctx, t.ID)
	}

	out := &LogoutResult{
		ClearCookie:            true,
		FrontChannelLogoutURLs: frontURLs,
	}
	redirect := strings.TrimSpace(in.PostLogoutRedirect)
	if redirect == "" {
		return out, nil
	}

	clientID, err := f.resolveLogoutClientID(ctx, in)
	if err != nil {
		return nil, err
	}
	client, err := f.clients.GetByClientID(ctx, f.tenantID(), clientID)
	if err != nil {
		return nil, fmt.Errorf("%w: unknown client for post_logout_redirect_uri", ErrInvalidRequest)
	}
	if !client.HasPostLogoutURI(redirect) {
		return nil, fmt.Errorf("%w: post_logout_redirect_uri is not registered", ErrInvalidRequest)
	}

	u, err := url.Parse(redirect)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid post_logout_redirect_uri", ErrInvalidRequest)
	}
	if in.State != "" {
		q := u.Query()
		q.Set("state", in.State)
		u.RawQuery = q.Encode()
	}
	out.RedirectTo = u.String()
	return out, nil
}

func (f *Flow) resolveLogoutTargets(ctx context.Context, in LogoutInput) []logoutTarget {
	scope := f.cfg.Session.LogoutScope
	if scope == "" {
		scope = config.LogoutScopeSession
	}

	switch scope {
	case config.LogoutScopeSubject:
		return f.logoutTargetsBySubject(ctx, in)
	case config.LogoutScopeDevice:
		return f.logoutTargetsByDevice(ctx, in)
	default:
		sid := f.resolveLogoutSessionID(ctx, in)
		if sid == uuid.Nil {
			return nil
		}
		subject := ""
		if sess := f.loadLogoutSession(ctx, in); sess != nil {
			subject = sess.Subject
		}
		if subject == "" {
			subject = f.subjectFromIDTokenHint(in.IDTokenHint)
		}
		return []logoutTarget{{ID: sid, Subject: subject}}
	}
}

func (f *Flow) logoutTargetsBySubject(ctx context.Context, in LogoutInput) []logoutTarget {
	subject := ""
	if sess := f.loadLogoutSession(ctx, in); sess != nil {
		subject = sess.Subject
	}
	if subject == "" {
		subject = f.subjectFromIDTokenHint(in.IDTokenHint)
	}
	if subject == "" {
		if sid := f.resolveLogoutSessionID(ctx, in); sid != uuid.Nil {
			return []logoutTarget{{ID: sid, Subject: ""}}
		}
		return nil
	}
	sessions, err := f.loginSessions.ListBySubject(ctx, f.tenantID(), subject)
	if err != nil {
		return nil
	}
	out := make([]logoutTarget, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, logoutTarget{ID: s.ID, Subject: s.Subject})
	}
	return out
}

func (f *Flow) logoutTargetsByDevice(ctx context.Context, in LogoutInput) []logoutTarget {
	deviceID := ""
	if sess := f.loadLogoutSession(ctx, in); sess != nil && strings.TrimSpace(sess.DeviceID) != "" {
		deviceID = strings.TrimSpace(sess.DeviceID)
	}
	if deviceID == "" {
		deviceID = normalizeDeviceID(in.DeviceIDFromCookie)
	}
	if deviceID == "" {
		if sid := f.resolveLogoutSessionID(ctx, in); sid != uuid.Nil {
			subject := ""
			if sess := f.loadLogoutSession(ctx, in); sess != nil {
				subject = sess.Subject
			}
			return []logoutTarget{{ID: sid, Subject: subject}}
		}
		return nil
	}
	sessions, err := f.loginSessions.ListByDeviceID(ctx, f.tenantID(), deviceID)
	if err != nil {
		return nil
	}
	out := make([]logoutTarget, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, logoutTarget{ID: s.ID, Subject: s.Subject})
	}
	return out
}

func (f *Flow) deleteOneLoginSession(ctx context.Context, sessionID uuid.UUID) {
	_ = f.loginSessions.Delete(ctx, sessionID)
	if f.tokens != nil {
		_ = f.tokens.RevokeRefreshTokensBySession(ctx, f.tenantID(), sessionID)
	}
}

func (f *Flow) loadLogoutSession(ctx context.Context, in LogoutInput) *domain.LoginSession {
	sid := f.resolveLogoutSessionID(ctx, in)
	if sid == uuid.Nil {
		return nil
	}
	sess, err := f.loginSessions.GetByID(ctx, sid)
	if err != nil || sess.TenantID != f.tenantID() {
		return nil
	}
	return sess
}

func (f *Flow) resolveLogoutSessionID(ctx context.Context, in LogoutInput) uuid.UUID {
	if sid, err := uuid.Parse(strings.TrimSpace(in.SessionIDFromCookie)); err == nil && sid != uuid.Nil {
		if sess, err := f.loginSessions.GetByID(ctx, sid); err == nil && sess.TenantID == f.tenantID() {
			return sess.ID
		}
		// Cookie present but session gone — still treat as this sid for revoke best-effort.
		return sid
	}
	if in.IDTokenHint == "" || f.idTokens == nil {
		return uuid.Nil
	}
	claims, err := f.idTokens.ParseHint(in.IDTokenHint)
	if err != nil {
		return uuid.Nil
	}
	if iss, _ := claims["iss"].(string); iss != "" && strings.TrimRight(iss, "/") != f.issuer() {
		return uuid.Nil
	}
	sidStr, _ := claims["sid"].(string)
	sid, err := uuid.Parse(strings.TrimSpace(sidStr))
	if err != nil || sid == uuid.Nil {
		return uuid.Nil
	}
	return sid
}

func (f *Flow) subjectFromIDTokenHint(hint string) string {
	if hint == "" || f.idTokens == nil {
		return ""
	}
	claims, err := f.idTokens.ParseHint(hint)
	if err != nil {
		return ""
	}
	if iss, _ := claims["iss"].(string); iss != "" && strings.TrimRight(iss, "/") != f.issuer() {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return strings.TrimSpace(sub)
}

func (f *Flow) resolveLogoutClientID(_ context.Context, in LogoutInput) (string, error) {
	if id := strings.TrimSpace(in.ClientID); id != "" {
		return id, nil
	}
	if in.IDTokenHint == "" || f.idTokens == nil {
		return "", fmt.Errorf("%w: client_id or id_token_hint required with post_logout_redirect_uri", ErrInvalidRequest)
	}
	claims, err := f.idTokens.ParseHint(in.IDTokenHint)
	if err != nil {
		return "", fmt.Errorf("%w: invalid id_token_hint", ErrInvalidRequest)
	}
	switch aud := claims["aud"].(type) {
	case string:
		if strings.TrimSpace(aud) != "" {
			return aud, nil
		}
	case []any:
		if len(aud) > 0 {
			if s, ok := aud[0].(string); ok && s != "" {
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("%w: cannot resolve client_id from id_token_hint", ErrInvalidRequest)
}

// normalizeDeviceID returns a trimmed UUID string or empty if invalid.
func normalizeDeviceID(raw string) string {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil || id == uuid.Nil {
		return ""
	}
	return id.String()
}
