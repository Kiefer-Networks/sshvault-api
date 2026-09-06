package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// serveHTTP uses one total deadline across graceful drain, forced close, and
// cleanup. Misbehaving handlers or cleanup cannot prevent process return.
func serveHTTP(ctx context.Context, srv *http.Server, listener net.Listener, cleanup func(context.Context) error) error {
	return serveHTTPWithTimeout(ctx, srv, listener, cleanup, 30*time.Second)
}
func serveHTTPWithTimeout(ctx context.Context, srv *http.Server, listener net.Listener, cleanup func(context.Context) error, timeout time.Duration) error {
	result := make(chan error, 1)
	go func() { result <- srv.Serve(listener) }()
	var serveErr error
	select {
	case serveErr = <-result:
	case <-ctx.Done():
	}
	budget, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	grace, graceCancel := context.WithTimeout(budget, timeout-timeout/3)
	shutdownErr := srv.Shutdown(grace)
	graceCancel()
	if shutdownErr != nil {
		_ = srv.Close()
	}
	// Serve returns after the listener closes, independent of remaining handlers.
	if serveErr == nil {
		select {
		case serveErr = <-result:
		case <-budget.Done():
		}
	}
	cleanupResult := make(chan error, 1)
	go func() { cleanupResult <- cleanup(budget) }()
	var cleanupErr error
	select {
	case cleanupErr = <-cleanupResult:
	case <-budget.Done():
		cleanupErr = budget.Err()
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, shutdownErr, cleanupErr)
}

// runCleanup starts a fixed set of shutdown operations together under the same
// deadline, including operations whose underlying API has no context support.
func runCleanup(ctx context.Context, operations ...func(context.Context) error) error {
	results := make(chan error, len(operations))
	var wg sync.WaitGroup
	for _, operation := range operations {
		wg.Add(1)
		go func() { defer wg.Done(); results <- operation(ctx) }()
	}
	go func() { wg.Wait(); close(results) }()
	var errs []error
	for {
		select {
		case err, ok := <-results:
			if !ok {
				return errors.Join(errs...)
			}
			if err != nil {
				errs = append(errs, err)
			}
		case <-ctx.Done():
			return errors.Join(append(errs, ctx.Err())...)
		}
	}
}
