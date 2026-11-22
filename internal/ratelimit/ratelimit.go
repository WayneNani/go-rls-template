// Package ratelimit limits requests per client IP with a token bucket.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ponytail: one mutex and one map per limiter; shard or move to the proxy if it shows in profiles.
type Limiter struct {
	mu        sync.Mutex
	clients   map[string]*client
	rate      rate.Limit
	burst     int
	lastSweep time.Time
}

type client struct {
	limiter *rate.Limiter
	seen    time.Time
}

// PerIP allows each client IP `burst` requests at once, refilled at `r` per second.
func PerIP(r rate.Limit, burst int) *Limiter {
	return &Limiter{clients: map[string]*client{}, rate: r, burst: burst}
}

func (l *Limiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(ClientIP(r), time.Now()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) > time.Minute { // forget idle clients so the map cannot grow forever
		for k, c := range l.clients {
			if now.Sub(c.seen) > 10*time.Minute {
				delete(l.clients, k)
			}
		}
		l.lastSweep = now
	}
	c, ok := l.clients[ip]
	if !ok {
		c = &client{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.clients[ip] = c
	}
	c.seen = now
	return c.limiter.AllowN(now, 1)
}

// ClientIP is the TCP peer; rate limits and the audit log use it. Behind a reverse
// proxy all clients share the proxy's address: then read the client IP from the
// proxy's header here, trusting that header only when the request comes from the proxy.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
