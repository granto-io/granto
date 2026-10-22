package domain

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// Audit actor / subject / outcome values.
const (
	AuditActorUser   = "user"
	AuditActorClient = "client"
	AuditActorAdmin  = "admin"
	AuditActorSystem = "system"

	AuditSubjectUser    = "user"
	AuditSubjectClient  = "client"
	AuditSubjectSession = "session"
	AuditSubjectToken   = "token"

	AuditOutcomeSuccess = "success"
	AuditOutcomeFailure = "failure"
)

// Audit event_type catalog (MVP).
const (
	AuditEventLoginChallengeCreated   = "login_challenge_created"
	AuditEventLoginAccepted           = "login_accepted"
	AuditEventLoginRejected           = "login_rejected"
	AuditEventConsentChallengeCreated = "consent_challenge_created"
	AuditEventConsentAccepted         = "consent_accepted"
	AuditEventConsentRejected         = "consent_rejected"
	AuditEventSessionCreated          = "session_created"
	AuditEventSessionDeleted          = "session_deleted"
	AuditEventTokenIssued             = "token_issued"
	AuditEventTokenRevoked            = "token_revoked"
	AuditEventLogout                  = "logout"
	AuditEventClientCreated           = "client_created"
	AuditEventClientUpdated           = "client_updated"
	AuditEventClientDeleted           = "client_deleted"
	AuditEventConsentGrantRevoked     = "consent_grant_revoked"
	AuditEventAuthorizeError          = "authorize_error"
	AuditEventTokenError              = "token_error"
)

// AuditEvent is one audit stream event (serialized to outbox / channels as JSON).
type AuditEvent struct {
	TenantID    uuid.UUID
	EventType   string
	ActorType   string
	ActorID     string
	SubjectType string
	SubjectID   string
	ClientID    string
	SessionID   string
	IPAddress   net.IP
	UserAgent   string
	Outcome     string
	ErrorCode   string
	Metadata    map[string]any
	CreatedAt   time.Time
}
