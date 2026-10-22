package oauth2

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// logoutTarget is one LoginSession that logout will end (and notify RPs about).
type logoutTarget struct {
	ID      uuid.UUID
	Subject string
}

type backChannelTask struct {
	URL      string
	Token    string
	ClientID string
}

// SetHTTPClient overrides the HTTP client used for back-channel logout (tests).
func (f *Flow) SetHTTPClient(c *http.Client) {
	f.httpClient = c
}

func (f *Flow) backChannelHTTPClient() *http.Client {
	if f.httpClient != nil {
		return f.httpClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// prepareSessionChannels lists RPs that received tokens for the session and builds
// front-channel iframe URLs + back-channel POST tasks. Call before deleting the
// session (RevokeRefreshTokensBySession clears the session_clients index).
func (f *Flow) prepareSessionChannels(ctx context.Context, target logoutTarget) (frontURLs []string, tasks []backChannelTask) {
	if f.tokens == nil || target.ID == uuid.Nil {
		return nil, nil
	}
	clientIDs, err := f.tokens.ListClientIDsBySession(ctx, f.tenantID(), target.ID)
	if err != nil || len(clientIDs) == 0 {
		return nil, nil
	}
	issuer := f.issuer()
	for _, cid := range clientIDs {
		client, err := f.clients.GetByClientID(ctx, f.tenantID(), cid)
		if err != nil {
			continue
		}
		if u := strings.TrimSpace(client.FrontChannelLogoutURI); u != "" {
			if front, err := buildFrontChannelLogoutURL(u, issuer, target.ID); err == nil {
				frontURLs = append(frontURLs, front)
			}
		}
		if u := strings.TrimSpace(client.BackChannelLogoutURI); u != "" && f.idTokens != nil {
			token, err := f.idTokens.IssueLogoutToken(ctx, cid, target.Subject, target.ID)
			if err != nil {
				continue
			}
			tasks = append(tasks, backChannelTask{URL: u, Token: token, ClientID: cid})
		}
	}
	return frontURLs, tasks
}

func buildFrontChannelLogoutURL(rawURI, issuer string, sessionID uuid.UUID) (string, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("iss", issuer)
	q.Set("sid", sessionID.String())
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (f *Flow) dispatchBackChannelLogout(tasks []backChannelTask) {
	if len(tasks) == 0 {
		return
	}
	client := f.backChannelHTTPClient()
	for _, t := range tasks {
		go func(t backChannelTask) {
			body := url.Values{"logout_token": {t.Token}}.Encode()
			req, err := http.NewRequest(http.MethodPost, t.URL, strings.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			res, err := client.Do(req)
			if err != nil {
				return
			}
			defer res.Body.Close() //nolint:errcheck
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		}(t)
	}
}

func (f *Flow) notifyBackChannelForSession(ctx context.Context, sess *domain.LoginSession) {
	if sess == nil {
		return
	}
	_, tasks := f.prepareSessionChannels(ctx, logoutTarget{ID: sess.ID, Subject: sess.Subject})
	f.dispatchBackChannelLogout(tasks)
}
