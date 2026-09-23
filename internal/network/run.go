package network

import (
	"context"
	"fmt"
	"io"
	"time"
)

// RunOptions describes a local runtime invocation, not an authorized World
// Execution. The caller must supply a trusted policy and a dedicated workdir.
type RunOptions struct {
	Policy  Policy
	Workdir string
	Command []string
	Timeout time.Duration
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

func Run(ctx context.Context, options RunOptions) (int, error) {
	if err := options.Policy.Validate(); err != nil {
		return 125, err
	}
	if len(options.Command) == 0 || options.Command[0] == "" {
		return 125, fmt.Errorf("command is required")
	}
	if options.Timeout <= 0 || options.Timeout > 24*time.Hour {
		return 125, fmt.Errorf("timeout must be positive and at most 24h")
	}
	return run(ctx, options)
}
