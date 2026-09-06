package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeHTTPDrainsRequestsBeforeCleanupAndWaitsForCleanup(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	entered, release, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	cleaning, cleaned := make(chan struct{}), make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "completed")
		close(handlerDone)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- serveHTTP(ctx, srv, listener, func() {
			select {
			case <-handlerDone:
			default:
				t.Error("cleanup ran before request completed")
			}
			close(cleaning)
			<-cleaned
		})
	}()
	response := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			data, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			err = readErr
			if string(data) != "completed" {
				t.Errorf("response truncated: %q", data)
			}
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	close(release)
	select {
	case <-cleaning:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not start")
	}
	select {
	case err := <-result:
		t.Fatalf("server returned before cleanup: %v", err)
	default:
	}
	close(cleaned)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := <-response; err != nil {
		t.Fatal(err)
	}
}

func TestForcedShutdownWaitsForCanceledHandler(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	cleaned := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-release
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- serveHTTPWithTimeout(ctx, srv, listener, func() { close(cleaned) }, time.Millisecond)
	}()
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not canceled")
	}
	select {
	case <-cleaned:
		t.Error("cleanup ran while canceled handler was active")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("forced shutdown must report its timeout")
	}
	<-cleaned
}
