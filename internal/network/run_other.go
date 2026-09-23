//go:build !darwin

package network

import (
	"context"
	"fmt"
)

func run(context.Context, RunOptions) (int, error) {
	return 125, fmt.Errorf("network isolation backend requires macOS; refusing unsandboxed execution")
}
