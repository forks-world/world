package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func endpoint(t *testing.T, address string) Endpoint {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(port)
	return Endpoint{Host: host, Port: n}
}

func startTestProxy(t *testing.T, destinations ...Endpoint) *Proxy {
	t.Helper()
	p, err := StartProxy(context.Background(), Policy{NetworkID: t.Name(), Allow: destinations})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestProxyAllowDenyAndIsolation(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "network-a") }))
	t.Cleanup(a.Close)
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "network-b") }))
	t.Cleanup(b.Close)
	pa := startTestProxy(t, endpoint(t, a.Listener.Addr().String()))
	pb := startTestProxy(t, endpoint(t, b.Listener.Addr().String()))
	for _, tc := range []struct {
		name   string
		proxy  *Proxy
		target string
		status int
	}{
		{"a-own", pa, a.URL, 200}, {"a-other", pa, b.URL, 403},
		{"b-own", pb, b.URL, 200}, {"b-other", pb, a.URL, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, _ := url.Parse(tc.proxy.URL())
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 3 * time.Second}
			defer client.CloseIdleConnections()
			resp, err := client.Get(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestProxyCloseRevokesExistingTunnel(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	p := startTestProxy(t, endpoint(t, ln.Addr().String()))
	c, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", ln.Addr(), ln.Addr(), p.authorization())
	reader := bufio.NewReader(c)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	fmt.Fprint(c, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q %v", buf, err)
	}
	p.Close()
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("tunnel still readable after revocation")
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream remains connected")
	}
}

func TestProxyRejectsHostnameResolvingToLoopback(t *testing.T) {
	p, err := StartProxy(context.Background(), Policy{NetworkID: "a", Allow: []Endpoint{{Host: "localhost", Port: 80}}})
	if err == nil {
		p.Close()
		t.Fatal("hostname resolving to loopback accepted")
	}
	if !strings.Contains(err.Error(), "non-public") {
		t.Fatal(err)
	}
}

func TestProxyCredentialsAndConcurrentClose(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential leaked upstream")
		}
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	p := startTestProxy(t, endpoint(t, upstream.Listener.Addr().String()))
	other := startTestProxy(t, endpoint(t, upstream.Listener.Addr().String()))
	for _, auth := range []string{"", other.authorization(), p.authorization()} {
		request := httptest.NewRequest("GET", upstream.URL, nil)
		request.Header.Set("Proxy-Authorization", auth)
		response := httptest.NewRecorder()
		p.ServeHTTP(response, request)
		want := 407
		if auth == p.authorization() {
			want = 200
		}
		if response.Code != want {
			t.Fatalf("got status %d, want %d", response.Code, want)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.Close() }()
	}
	wg.Wait()
	if c, err := net.DialTimeout("tcp", p.listener.Addr().String(), time.Second); err == nil {
		c.Close()
		t.Fatal("listener survived Close")
	}
}

func TestProxyOwnsBothLoopbackFamilies(t *testing.T) {
	p := startTestProxy(t)
	for _, address := range []string{p.listener.Addr().String(), p.listener6.Addr().String()} {
		ln, err := net.Listen("tcp", address)
		if err == nil {
			ln.Close()
			t.Fatalf("proxy address can be stolen: %s", address)
		}
		c, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		fmt.Fprint(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
		c.Close()
		if err != nil || resp.StatusCode != 407 {
			t.Fatalf("%s is not authenticated proxy: %v %v", address, resp, err)
		}
	}
}

func TestProxyContextCancellationRevokesListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p, err := StartProxy(ctx, Policy{NetworkID: "cancel"})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer p.Close()
	cancel()
	select {
	case <-p.closeDone:
	case <-time.After(time.Second):
		t.Fatal("cancel did not close proxy")
	}
}
