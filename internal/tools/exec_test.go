package tools

import (
	"fmt"
	"testing"
	"time"
)

func TestIsTimeoutRecognizesWrappedTimeout(t *testing.T) {
	err := fmt.Errorf("pipeline step failed: %w", TimeoutError{
		Bin:     "subfinder",
		Args:    []string{"-d", "example.com"},
		Timeout: 20 * time.Minute,
	})

	if !IsTimeout(err) {
		t.Fatal("IsTimeout returned false for wrapped TimeoutError")
	}
}

func TestTimeoutErrorMessage(t *testing.T) {
	err := TimeoutError{Bin: "httpx", Timeout: 90 * time.Second}
	if got, want := err.Error(), "httpx timed out after 1m30s"; got != want {
		t.Fatalf("Error() = %q; want %q", got, want)
	}
}
