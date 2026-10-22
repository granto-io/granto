// Package admin implements Admin API gRPC services (grpc-gateway REST adapters
// are generated under gen/admin/v1).
//
// Contracts live in api/admin/v1/*.proto. Do not edit gen/.
//
// Layout (single package, files by domain):
//
//	client.go, client_mapper.go, client_secret.go
//	oauth2.go, oauth2_errors.go
//	session.go                 // LoginSession Admin CRUD / Hydra-like revoke
//	server.go, auth.go, tenant.go
//	errors.go, doc.go
package admin
