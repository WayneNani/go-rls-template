package ratelimit

import (
	"testing"
	"time"
)

func TestPerIP(t *testing.T) {
	l := PerIP(1, 3) // 3 at once, then 1 per second
	now := time.Now()

	for i := range 3 {
		if !l.allow("10.0.0.1", now) {
			t.Fatalf("request %d within burst was denied", i+1)
		}
	}
	if l.allow("10.0.0.1", now) {
		t.Error("request beyond burst was allowed")
	}
	if !l.allow("10.0.0.2", now) {
		t.Error("another IP was limited by the first one's traffic")
	}
	if !l.allow("10.0.0.1", now.Add(time.Second)) {
		t.Error("token was not refilled after one second")
	}

	l.allow("10.0.0.3", now.Add(20*time.Minute)) // triggers the sweep
	if _, ok := l.clients["10.0.0.1"]; ok {
		t.Error("idle client was not forgotten")
	}
}
