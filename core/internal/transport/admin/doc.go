// Package admin implements Admin API gRPC services (grpc-gateway REST adapters
// are generated under gen/admin/v1).
//
// Contracts live in api/admin/v1/*.proto. Do not edit gen/.
//
// Layout (single package, files by domain):
//
//	client.go, client_mapper.go, client_secret.go
//	server.go, auth.go         // gRPC + gateway lifecycle / interceptors
//	session.go, …              // later
//	errors.go, doc.go          // shared
package admin
