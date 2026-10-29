// Package logx rate-limits repetitive log lines so a telemetry flood cannot
// turn the journal into the bottleneck (or bury the lines that matter).
//
// Security-relevant lines (containment refusals, tamper evidence, chain
// breaks) must NOT go through this: they are rare by construction and are
// also audited. It is for per-event chatter: zone transitions, process
// exits, per-connection errors.
package logx

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type bucket struct {
	next       time.Time
	suppressed uint64
}

// Limiter allows one line per key per interval and counts the rest. The
// next allowed line for the key reports how many were suppressed, so the
// volume is still visible. Memory is bounded by maxKeys.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	maxKeys  int
	now      func() time.Time
	keys     map[string]*bucket
	out      func(string)
}

func New(interval time.Duration, maxKeys int) *Limiter {
	return &Limiter{interval: interval, maxKeys: maxKeys, now: time.Now,
		keys: map[string]*bucket{}, out: func(s string) { log.Print(s) }}
}

// Printf logs format/args under key, or counts it as suppressed.
func (l *Limiter) Printf(key, format string, args ...any) {
	l.mu.Lock()
	t := l.now()
	b, ok := l.keys[key]
	if !ok {
		if len(l.keys) >= l.maxKeys {
			l.sweepLocked(t)
		}
		if len(l.keys) >= l.maxKeys { // still full: share one overflow bucket
			key = "~overflow"
			if b, ok = l.keys[key]; !ok {
				b = &bucket{}
				l.keys[key] = b
			}
		} else {
			b = &bucket{}
			l.keys[key] = b
		}
	}
	if t.Before(b.next) {
		b.suppressed++
		l.mu.Unlock()
		return
	}
	n := b.suppressed
	b.suppressed = 0
	b.next = t.Add(l.interval)
	l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	if n > 0 {
		msg = fmt.Sprintf("%s (+%d similar suppressed)", msg, n)
	}
	l.out(msg)
}

func (l *Limiter) sweepLocked(t time.Time) {
	for k, b := range l.keys {
		if t.After(b.next) && b.suppressed == 0 {
			delete(l.keys, k)
		}
	}
}
