package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// serveHTTP owns the server lifecycle. Cleanup runs only after HTTP shutdown,
// and completes before the caller may close database connections or exit.
func serveHTTP(ctx context.Context, srv *http.Server, listener net.Listener, cleanup func()) error {
	return serveHTTPWithTimeout(ctx, srv, listener, cleanup, 30*time.Second)
}

func serveHTTPWithTimeout(ctx context.Context, srv *http.Server, listener net.Listener, cleanup func(), timeout time.Duration) error {
	defer cleanup()
	// Close cancels connections but does not wait for handlers to return.
	// Gate additions before waiting so late-dispatched requests cannot race cleanup.
	var mu sync.Mutex
	var active sync.WaitGroup
	closing := false
	handler := srv.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if closing {
			mu.Unlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		active.Add(1)
		mu.Unlock()
		defer active.Done()
		handler.ServeHTTP(w, r)
	})
	defer func() {
		mu.Lock()
		closing = true
		mu.Unlock()
		active.Wait()
	}()
	result := make(chan error, 1)
	go func() { result <- srv.Serve(listener) }()
	select {
	case err := <-result:
		_ = srv.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			_ = srv.Close()
		}
		<-result
		return err
	}
}
