//go:build !darwin

package network

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestUnsupportedPlatformFailsClosed(t *testing.T) {
	code, err := Run(context.Background(), RunOptions{Policy: Policy{NetworkID: "offline"}, Workdir: t.TempDir(), Command: []string{"/bin/true"}, Timeout: time.Second})
	if code != 125 || err == nil || !strings.Contains(err.Error(), "refusing unsandboxed") {
		t.Fatalf("got %d, %v", code, err)
	}
}
