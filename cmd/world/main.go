package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/forks-world/world/internal/network"
)

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) < 3 || os.Args[1] != "network" || os.Args[2] != "exec" {
		fmt.Fprintln(os.Stderr, "usage: world network exec --policy FILE --workdir DIR [--timeout 5m] -- COMMAND [ARGS...]")
		return 125
	}
	flags := flag.NewFlagSet("network exec", flag.ContinueOnError)
	policyPath := flags.String("policy", "", "trusted Network policy JSON file (required)")
	workdir := flags.String("workdir", "", "dedicated writable workspace (required)")
	timeout := flags.Duration("timeout", 5*time.Minute, "execution deadline, at most 24h")
	if err := flags.Parse(os.Args[3:]); err != nil {
		return 125
	}
	if *policyPath == "" || *workdir == "" {
		fmt.Fprintln(os.Stderr, "world: --policy and --workdir are required")
		return 125
	}
	f, err := os.Open(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "world:", err)
		return 125
	}
	policy, err := network.ReadPolicy(f)
	_ = f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "world:", err)
		return 125
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, err := network.Run(ctx, network.RunOptions{Policy: policy, Workdir: *workdir, Command: flags.Args(), Timeout: *timeout, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, "world:", err)
	}
	return code
}
