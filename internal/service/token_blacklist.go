package service

import (
	"sync"
	"time"
)

// TokenBlacklist stores revoked JWT token IDs with automatic cleanup.
type TokenBlacklist struct {
	mu      sync.RWMutex
	entries map[string]time.Time // jti -> expiry time
	quit    chan struct{}
}

func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{
		entries: make(map[string]time.Time),
		quit:    make(chan struct{}),
	}
}

// Add adds a token JTI to the blacklist with the given TTL (token's remaining lifetime).
func (b *TokenBlacklist) Add(jti string, ttl time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[jti] = time.Now().Add(ttl)
}

// IsBlacklisted checks if a token JTI is in the blacklist.
func (b *TokenBlacklist) IsBlacklisted(jti string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	expiry, exists := b.entries[jti]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

// StartCleanup starts a background goroutine that removes expired entries every 10 minutes.
func (b *TokenBlacklist) StartCleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				b.mu.Lock()
				now := time.Now()
				for jti, expiry := range b.entries {
					if now.After(expiry) {
						delete(b.entries, jti)
					}
				}
				b.mu.Unlock()
			case <-b.quit:
				ticker.Stop()
				return
			}
		}
	}()
}

// StopCleanup stops the background cleanup goroutine.
func (b *TokenBlacklist) StopCleanup() {
	close(b.quit)
}
