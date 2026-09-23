package network

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func run(ctx context.Context, options RunOptions) (int, error) {
	workdir, err := filepath.Abs(options.Workdir)
	if err != nil {
		return 125, err
	}
	workdir, err = filepath.EvalSymlinks(workdir)
	if err != nil {
		return 125, fmt.Errorf("workdir: %w", err)
	}
	info, err := os.Stat(workdir)
	if err != nil || !info.IsDir() {
		return 125, fmt.Errorf("workdir must be an existing directory")
	}
	home, _ := os.UserHomeDir()
	home, _ = filepath.EvalSymlinks(home)
	// Prevent broad writable roots that make host launch-agent injection trivial.
	if workdir == "/" || home == workdir || strings.HasPrefix(home, workdir+"/") {
		return 125, fmt.Errorf("workdir must be a dedicated workspace, not a home directory or its ancestor")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		return 125, fmt.Errorf("sandbox-exec unavailable; refusing unsandboxed execution: %w", err)
	}
	tmp, err := os.MkdirTemp("", "world-network-")
	if err != nil {
		return 125, err
	}
	defer os.RemoveAll(tmp)
	tmp, err = filepath.EvalSymlinks(tmp)
	if err != nil {
		return 125, err
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	var proxy *Proxy
	port := 0
	if len(options.Policy.Allow) > 0 {
		proxy, err = StartProxy(ctx, options.Policy)
		if err != nil {
			return 125, err
		}
		defer proxy.Close()
		port = proxy.Port()
	}
	profile := seatbeltProfile(workdir, tmp, port)
	// -p avoids writable policy-file races. No shell interpolation is used.
	args := append([]string{"-p", profile, "--"}, options.Command...)
	// A fresh, single-threaded descriptor guard also closes non-CLOEXEC FDs
	// inherited by the CLI. os/exec alone does not close such descriptors.
	launcherArgs := append([]string{"-c", closeDescriptorsScript, "world-fd-guard", "/usr/bin/sandbox-exec"}, args...)
	cmd := exec.Command("/bin/sh", launcherArgs...)
	cmd.Dir = workdir
	cmd.Env = executionEnv(tmp, workdir, proxy)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Always use pipes: never pass inherited sockets (including stdio) to the
	// workload. The descriptor guard closes all additional descriptors.
	if options.Stdin != nil {
		cmd.Stdin = readerOnly{options.Stdin}
	}
	if options.Stdout != nil {
		cmd.Stdout = writerOnly{options.Stdout}
	}
	if options.Stderr != nil {
		cmd.Stderr = writerOnly{options.Stderr}
	}
	cmd.WaitDelay = time.Second
	if err := ctx.Err(); err != nil {
		return 124, err
	}
	if err := cmd.Start(); err != nil {
		return 125, fmt.Errorf("start sandbox: %w", err)
	}
	finish := make(chan error, 1)
	go func() { finish <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-finish:
	case <-ctx.Done():
		// Revoke existing CONNECT tunnels before stopping the process group.
		if proxy != nil {
			proxy.Close()
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-finish
		return 124, ctx.Err()
	}
	if proxy != nil {
		proxy.Close()
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if waitErr == nil {
		return 0, nil
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		status := exitErr.Sys().(syscall.WaitStatus)
		if status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	return 125, fmt.Errorf("wait sandbox: %w", waitErr)
}

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

// Only descriptor numbers from /dev/fd enter eval; workload arguments remain
// separate positional parameters and are never interpolated into shell code.
const closeDescriptorsScript = `
for file in /dev/fd/*; do
  fd=${file##*/}
  case "$fd" in
    0|1|2) continue ;;
    ''|*[!0-9]*) exit 125 ;;
  esac
  eval "exec ${fd}>&-" || exit 125
done
exec "$@"
`

func seatbeltProfile(workdir, temp string, port int) string {
	profile := `(version 1)
(allow default)
(deny network*)
(deny mach-lookup)
(deny mach-register)
(deny ipc-posix*)
(deny ipc-sysv*)
(deny process-info*)
(allow process-info* (target self))
(deny signal)
(allow signal (target same-sandbox))
(deny file-write*)
`
	profile += "(allow file-write* (subpath " + strconv.Quote(workdir) + ") (subpath " + strconv.Quote(temp) + ") (literal \"/dev/null\"))\n"
	if port != 0 {
		profile += fmt.Sprintf("(allow network-outbound (remote tcp \"localhost:%d\"))\n", port)
	}
	return profile
}

func executionEnv(temp, workdir string, proxy *Proxy) []string {
	// Keep a small deterministic environment. In particular DYLD_* must not
	// reach sandbox-exec before it applies the policy; proxy bypass variables
	// and host service credentials are not inherited.
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin", "HOME=" + temp, "TMPDIR=" + temp, "PWD=" + workdir, "LANG=en_US.UTF-8"}
	if proxy != nil {
		for _, key := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"} {
			env = append(env, key+"="+proxy.URL())
		}
	}
	return append(env, "NO_PROXY=", "no_proxy=")
}
