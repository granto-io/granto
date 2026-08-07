package admin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/config"
)

// Server runs Admin gRPC and the grpc-gateway HTTP/JSON proxy.
// Lifecycle stop is driven by App (ShutdownHTTP / StopGRPC), not by ctx alone.
type Server struct {
	grpcSrv *grpc.Server
	httpSrv *http.Server
	gwConn  *grpc.ClientConn
}

// NewServer registers admin services on a gRPC server (auth interceptors applied).
func NewServer(clients adminv1.ClientServiceServer, cfg *config.Config) *Server {
	grpcSrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			bearerAuthInterceptor(cfg.Admin.Token),
			ipAllowlistInterceptor(cfg.Admin.AllowedIPs),
		),
	)
	adminv1.RegisterClientServiceServer(grpcSrv, clients)

	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	return &Server{grpcSrv: grpcSrv}
}

// ListenGRPC binds the gRPC port so the gateway can dial safely before Serve.
func (s *Server) ListenGRPC(addr string) (net.Listener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen admin grpc: %w", err)
	}
	return lis, nil
}

// ServeGRPC serves on an already-bound listener until StopGRPC is called.
func (s *Server) ServeGRPC(lis net.Listener) error {
	if err := s.grpcSrv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("admin grpc serve: %w", err)
	}
	return nil
}

// RunGateway starts the HTTP/JSON gateway proxying to grpcAddr until ShutdownHTTP.
func (s *Server) RunGateway(ctx context.Context, httpAddr, grpcAddr string) error {
	conn, err := grpc.NewClient(dialLocal(grpcAddr), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("admin gateway dial: %w", err)
	}
	s.gwConn = conn

	mux := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher),
	)
	if err := adminv1.RegisterClientServiceHandler(ctx, mux, conn); err != nil {
		_ = conn.Close()
		return fmt.Errorf("register client gateway: %w", err)
	}

	s.httpSrv = &http.Server{
		Addr:              httpAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	err = s.httpSrv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("admin gateway serve: %w", err)
	}
	return nil
}

// incomingHeaderMatcher forwards Authorization (and friends) into gRPC metadata
// so bearerAuthInterceptor sees Postman/curl Bearer tokens.
func incomingHeaderMatcher(key string) (string, bool) {
	switch strings.ToLower(key) {
	case "authorization":
		return "authorization", true
	default:
		return runtime.DefaultHeaderMatcher(key)
	}
}

func dialLocal(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		return "127.0.0.1" + addr
	}
	return addr
}

// ShutdownHTTP drains the gateway: no new connections; in-flight finish or ctx timeout.
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

// StopGRPC stops accepting new RPCs and waits for in-flight ones (or force-stops).
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
