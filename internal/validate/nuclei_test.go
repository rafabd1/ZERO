package validate

import (
	"fmt"
	"testing"
)

func TestIsNoTemplatesError(t *testing.T) {
	err := fmt.Errorf("nuclei failed: [\x1b[1;31mFTL\x1b[0m] Could not run nuclei: no templates provided for scan")
	if !isNoTemplatesError(err) {
		t.Fatal("isNoTemplatesError returned false for Nuclei no-template failure")
	}
}
