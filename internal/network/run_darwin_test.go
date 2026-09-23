package network

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This helper is the real workload executed by sandbox-exec; tests assert
// kernel EPERM, not merely a timeout or an unreachable endpoint.
func TestNetworkHelper(t *testing.T) {
	var args []string
	for i, arg := range os.Args {
		if arg == "--network-helper" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		return
	}
	var err error
	switch args[0] {
	case "dial":
		var c net.Conn
		c, err = net.DialTimeout(args[1], args[2], time.Second)
		if c != nil {
			c.Close()
		}
	case "listen":
		var ln net.Listener
		ln, err = net.Listen("tcp4", "127.0.0.1:0")
		if ln != nil {
			ln.Close()
		}
	case "http":
		proxy, _ := url.Parse(os.Getenv("HTTP_PROXY"))
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 3 * time.Second}
		var resp *http.Response
		resp, err = client.Get(args[1])
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Printf("%d %s", resp.StatusCode, body)
			if resp.StatusCode != 200 {
				os.Exit(23)
			}
		}
	case "write":
		err = os.WriteFile(args[1], []byte("escape"), 0600)
	case "inherited-socket":
		fd, _ := strconv.Atoi(args[1])
		_, err := syscall.Getpeername(fd)
		if err == nil {
			os.Exit(99)
		}
		fmt.Print("descriptor-closed")
	default:
		os.Exit(99)
	}
	if err != nil {
		fmt.Println(err)
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			os.Exit(77)
		}
		os.Exit(78)
	}
	os.Exit(0)
}

func helperCommand(t *testing.T, args ...string) []string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return append([]string{binary, "-test.run=^TestNetworkHelper$", "--", "--network-helper"}, args...)
}

func sandboxRun(t *testing.T, p Policy, command []string) (int, string) {
	t.Helper()
	var output bytes.Buffer
	code, err := Run(context.Background(), RunOptions{Policy: p, Workdir: t.TempDir(), Command: command, Timeout: 10 * time.Second, Stdout: &output, Stderr: &output})
	if err != nil {
		t.Fatalf("sandbox infrastructure error: %v; output: %s", err, &output)
	}
	return code, output.String()
}

func TestDarwinKernelDeniesSocketsAndChildren(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	// Keep Unix path below Darwin's socket path length limit.
	unixDir, err := os.MkdirTemp("/tmp", "world-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(unixDir)
	unix, err := net.Listen("unix", filepath.Join(unixDir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close()
	probes := [][]string{{"dial", "tcp4", tcp.Addr().String()}, {"dial", "udp4", udp.LocalAddr().String()}, {"dial", "unix", unix.Addr().String()}}
	if ipv6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer ipv6.Close()
		probes = append(probes, []string{"dial", "tcp6", ipv6.Addr().String()})
	} else {
		t.Fatal("IPv6 fixture unavailable:", err)
	}
	for _, probe := range probes {
		t.Run(probe[1], func(t *testing.T) {
			command := helperCommand(t, probe...)
			if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("host control failed: %s %v", output, err)
			}
			for _, child := range []bool{false, true} {
				cmd := command
				if child {
					cmd = append([]string{"/bin/sh", "-c", `"$@"; result=$?; exit "$result"`, "child"}, command...)
				}
				code, out := sandboxRun(t, Policy{NetworkID: "offline"}, cmd)
				if code != 77 {
					t.Fatalf("child=%v: want kernel denial 77, got %d: %s", child, code, out)
				}
			}
		})
	}
	code, out := sandboxRun(t, Policy{NetworkID: "offline"}, helperCommand(t, "listen"))
	if code != 77 {
		t.Fatalf("listen: %d %s", code, out)
	}
}

func TestDarwinNetworkAllowlist(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "allowed") }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "forbidden") }))
	defer b.Close()
	otherProxy := startTestProxy(t, endpoint(t, b.Listener.Addr().String()))
	p := Policy{NetworkID: "network-a", Allow: []Endpoint{endpoint(t, a.Listener.Addr().String())}}
	for _, tc := range []struct {
		name     string
		command  []string
		want     int
		contains string
	}{
		{"proxy-allow", helperCommand(t, "http", a.URL), 0, "200 allowed"},
		{"proxy-deny", helperCommand(t, "http", b.URL), 23, "403"},
		{"direct-allowed-destination-denied", helperCommand(t, "dial", "tcp", a.Listener.Addr().String()), 77, ""},
		{"other-network-proxy-denied", helperCommand(t, "dial", "tcp", otherProxy.listener.Addr().String()), 77, ""},
		{"curl-http", []string{"/usr/bin/curl", "--fail", "--silent", "--show-error", a.URL}, 0, "allowed"},
		{"curl-connect", []string{"/usr/bin/curl", "--proxytunnel", "--fail", "--silent", "--show-error", a.URL}, 0, "allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := sandboxRun(t, p, tc.command)
			if code != tc.want || !strings.Contains(out, tc.contains) {
				t.Fatalf("got %d %q, want %d containing %q", code, out, tc.want, tc.contains)
			}
		})
	}
}

func TestDarwinExecutionLifecycle(t *testing.T) {
	code, out := sandboxRun(t, Policy{NetworkID: "offline"}, []string{"/bin/sh", "-c", "echo running; exit 42"})
	if code != 42 || !strings.Contains(out, "running") {
		t.Fatalf("exit propagation: %d %q", code, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	code, err := Run(ctx, RunOptions{Policy: Policy{NetworkID: "offline"}, Workdir: t.TempDir(), Command: []string{"/bin/sleep", "30"}, Timeout: time.Minute})
	if code != 124 || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout: %d %v duration=%v", code, err, time.Since(start))
	}
	code, err = Run(context.Background(), RunOptions{Policy: Policy{NetworkID: "offline"}, Workdir: t.TempDir(), Command: []string{"/bin/true"}, Timeout: 0})
	if code != 125 || err == nil {
		t.Fatal("accepted unlimited execution")
	}
}

func TestDarwinHostEscapeGuards(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "launch-agent")
	code, out := sandboxRun(t, Policy{NetworkID: "offline"}, helperCommand(t, "write", outside))
	if code != 77 {
		t.Fatalf("host write: %d %s", code, out)
	}
	code, out = sandboxRun(t, Policy{NetworkID: "offline"}, []string{"/bin/launchctl", "list"})
	if code == 0 {
		t.Fatalf("launchd access allowed: %s", out)
	}
}

func TestDarwinHTTPSConnect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "tls-ok") }))
	defer server.Close()
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	p := Policy{NetworkID: "tls", Allow: []Endpoint{endpoint(t, server.Listener.Addr().String())}}
	code, out := sandboxRun(t, p, []string{"/usr/bin/curl", "--fail", "--silent", "--show-error", "--cacert", certFile, server.URL})
	if code != 0 || out != "tls-ok" {
		t.Fatalf("HTTPS: %d %s", code, out)
	}
}

func TestDarwinConcurrentNetworks(t *testing.T) {
	for i := 0; i < 4; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "own-network") }))
			defer server.Close()
			p := Policy{NetworkID: t.Name(), Allow: []Endpoint{endpoint(t, server.Listener.Addr().String())}}
			code, out := sandboxRun(t, p, helperCommand(t, "http", server.URL))
			if code != 0 || !strings.Contains(out, "own-network") {
				t.Fatalf("concurrent execution: %d %s", code, out)
			}
		})
	}
}

func TestDarwinClosesInheritedSocket(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	command := helperCommand(t, "inherited-socket", strconv.Itoa(fds[0]))
	err = exec.Command(command[0], command[1:]...).Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 99 {
		t.Fatalf("host control did not inherit socket: %v", err)
	}
	code, out := sandboxRun(t, Policy{NetworkID: "offline"}, command)
	if code != 0 || out != "descriptor-closed" {
		t.Fatalf("inherited socket survived: %d %s", code, out)
	}
}

func TestDarwinOpenStdinDoesNotDelayExit(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	code, err := Run(context.Background(), RunOptions{Policy: Policy{NetworkID: "offline"}, Workdir: t.TempDir(), Command: []string{"/bin/echo", "done"}, Timeout: 3 * time.Second, Stdin: reader})
	if code != 0 || err != nil {
		t.Fatalf("open stdin prevented normal exit: %d %v", code, err)
	}
}

func TestDarwinRejectsSocketStdin(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fds[0]), "socket-input")
	defer input.Close()
	defer syscall.Close(fds[1])
	code, err := Run(context.Background(), RunOptions{Policy: Policy{NetworkID: "offline"}, Workdir: t.TempDir(), Command: []string{"/bin/echo", "must-not-run"}, Timeout: time.Second, Stdin: input})
	if code != 125 || err == nil || !strings.Contains(err.Error(), "socket stdin") {
		t.Fatalf("socket stdin accepted: %d %v", code, err)
	}
}
