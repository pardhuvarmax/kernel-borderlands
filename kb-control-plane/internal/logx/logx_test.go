package logx

import (
	"strings"
	"testing"
	"time"
)

func TestLimiterSuppressesAndReports(t *testing.T) {
	var lines []string
	now := time.Unix(0, 0)
	l := New(time.Second, 4)
	l.now = func() time.Time { return now }
	l.out = func(s string) { lines = append(lines, s) }

	for i := 0; i < 1000; i++ {
		l.Printf("zone:42", "Zone PID=42 hop %d", i)
	}
	if len(lines) != 1 {
		t.Fatalf("flood must emit one line, got %d", len(lines))
	}
	now = now.Add(2 * time.Second)
	l.Printf("zone:42", "Zone PID=42 again")
	if len(lines) != 2 || !strings.Contains(lines[1], "+999 similar suppressed") {
		t.Fatalf("second line must report suppressed count, got %v", lines)
	}
}

func TestLimiterBoundsKeys(t *testing.T) {
	l := New(time.Hour, 8)
	l.out = func(string) {}
	for i := 0; i < 10000; i++ {
		l.Printf(strings.Repeat("k", 1)+string(rune('a'+i%26))+time.Duration(i).String(), "x")
	}
	if len(l.keys) > 9 { // maxKeys + the shared overflow bucket
		t.Fatalf("key map unbounded: %d", len(l.keys))
	}
}
