// Package identity implements the IdentityService gRPC server and its
// grpc-gateway HTTP/JSON proxy.
package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	identityv1 "github.com/granto-io/granto/identity/gen/identity/v1"
)

// Server runs IdentityService gRPC and the grpc-gateway HTTP/JSON proxy.
type Server struct {
	grpcSrv *grpc.Server
	httpSrv *http.Server
	gwConn  *grpc.ClientConn
}

// NewServer registers the identity service on a gRPC server.
func NewServer(svc identityv1.IdentityServiceServer) *Server {
	grpcSrv := grpc.NewServer()
	identityv1.RegisterIdentityServiceServer(grpcSrv, svc)

	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	return &Server{grpcSrv: grpcSrv}
}

// ListenGRPC binds the gRPC port so the gateway can dial safely before Serve.
func (s *Server) ListenGRPC(addr string) (net.Listener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen identity grpc: %w", err)
	}
	return lis, nil
}

// ServeGRPC serves on an already-bound listener until StopGRPC is called.
func (s *Server) ServeGRPC(lis net.Listener) error {
	if err := s.grpcSrv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("identity grpc serve: %w", err)
	}
	return nil
}

// RunGateway starts the HTTP/JSON gateway proxying to grpcAddr until ShutdownHTTP.
func (s *Server) RunGateway(ctx context.Context, httpAddr, grpcAddr string) error {
	conn, err := grpc.NewClient(dialLocal(grpcAddr), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("identity gateway dial: %w", err)
	}
	s.gwConn = conn

	mux := runtime.NewServeMux()
	if err := identityv1.RegisterIdentityServiceHandler(ctx, mux, conn); err != nil {
		_ = conn.Close()
		return fmt.Errorf("register identity gateway: %w", err)
	}
	s.httpSrv = &http.Server{
		Addr:              httpAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	err = s.httpSrv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("identity gateway serve: %w", err)
	}
	return nil
}

// dialLocal rewrites a port-only listen addr (":4456") to a loopback dial
// target for the in-process gateway.
func dialLocal(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		return "127.0.0.1" + addr
	}
	return addr
}

// ShutdownHTTP drains the gateway.
func (s *Server) ShutdownHTTP(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	err := s.httpSrv.Shutdown(ctx)
	if s.gwConn != nil {
		_ = s.gwConn.Close()
		s.gwConn = nil
	}
	return err
}

// StopGRPC stops accepting new RPCs and waits for in-flight ones.
func (s *Server) StopGRPC(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.grpcSrv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.grpcSrv.Stop()
	}
}
