package audit

import (
	"context"
	"sync"
	"testing"
)

func TestLogAfterStopDoesNotPanic(t *testing.T) {
	l := NewNopLogger()
	l.Stop(context.Background())
	l.Log(&Entry{Category: CatSystem, Action: ActShutdown})
}

func TestConcurrentLogAndStop(t *testing.T) {
	l := NewNopLogger()
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				l.Log(&Entry{Category: CatAuth, Action: ActLogin})
			}
		}()
	}
	l.Stop(context.Background())
	wg.Wait()
}
