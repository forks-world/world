package network

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Proxy owns a listener and immutable, resolved policy for one execution.
// Listeners are allocated by the kernel and held until Close; there is no
// shared global proxy or reserve-port-then-rebind race between Networks.
type Proxy struct {
	listener  net.Listener
	listener6 net.Listener
	server    *http.Server
	transport *http.Transport
	routes    map[string][]string
	token     string
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	conns     map[*trackedConn]struct{}
	done      chan struct{}
	closeDone chan struct{}
}

func StartProxy(ctx context.Context, policy Policy) (*Proxy, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	routes := make(map[string][]string)
	for _, endpoint := range policy.Allow {
		host, _ := canonicalHost(endpoint.Host)
		var addresses []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			addresses = []netip.Addr{ip}
		} else {
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			ips, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip", host)
			cancel()
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("resolve allowed host %q: %v", host, err)
			}
			for _, ip := range ips {
				ip = ip.Unmap()
				// Private/local services must be granted as explicit IP literals.
				if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					return nil, fmt.Errorf("host %q resolves to non-public address; authorize a literal IP explicitly", host)
				}
				addresses = append(addresses, ip)
			}
		}
		key := authority(host, endpoint.Port)
		for _, ip := range addresses {
			routes[key] = append(routes[key], authority(ip.String(), endpoint.Port))
		}
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	// Seatbelt's localhost filter covers both IP families. Hold both ports
	// before admitting a workload, or an unrelated IPv6 service could occupy
	// the same allowed port and bypass the proxy's destination policy.
	ln6, err := net.Listen("tcp6", authority("::1", ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("reserve IPv6 proxy endpoint: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		ln.Close()
		ln6.Close()
		cancel()
		return nil, err
	}
	p := &Proxy{listener: ln, listener6: ln6, routes: routes, token: base64.RawURLEncoding.EncodeToString(secret), cancel: cancel, conns: make(map[*trackedConn]struct{}), done: make(chan struct{}), closeDone: make(chan struct{})}
	p.transport = &http.Transport{Proxy: nil, DialContext: p.dial, DisableKeepAlives: true, ResponseHeaderTimeout: 30 * time.Second}
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	var serving sync.WaitGroup
	for _, listener := range []net.Listener{ln, ln6} {
		serving.Add(1)
		go func() {
			defer serving.Done()
			_ = p.server.Serve(trackedListener{Listener: listener, proxy: p})
			cancel()
		}()
	}
	go func() { serving.Wait(); close(p.done) }()
	go func() {
		select {
		case <-ctx.Done():
		case <-p.done:
		}
		p.Close()
	}()
	return p, nil
}

func (p *Proxy) Port() int { return p.listener.Addr().(*net.TCPAddr).Port }

// URL contains a per-execution credential; do not log it.
func (p *Proxy) URL() string { return "http://world:" + p.token + "@" + p.listener.Addr().String() }

func (p *Proxy) authorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("world:"+p.token))
}

func (p *Proxy) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.closeDone
		return
	}
	p.closed = true
	connections := make([]*trackedConn, 0, len(p.conns))
	for c := range p.conns {
		connections = append(connections, c)
	}
	p.mu.Unlock()
	defer close(p.closeDone)
	p.cancel()
	_ = p.listener.Close()
	_ = p.listener6.Close()
	_ = p.server.Close()
	p.transport.CloseIdleConnections()
	for _, c := range connections {
		_ = c.Close()
	}
	<-p.done
}

func (p *Proxy) permitted(address string) (string, bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", false
	}
	host, err = canonicalHost(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 {
		return "", false
	}
	key := authority(host, n)
	_, ok := p.routes[key]
	return key, ok
}

func (p *Proxy) dial(ctx context.Context, _, address string) (net.Conn, error) {
	key, ok := p.permitted(address)
	if !ok {
		return nil, fmt.Errorf("destination denied")
	}
	var last error
	for _, pinned := range p.routes[key] {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", pinned)
		if err == nil {
			return p.track(c)
		}
		last = err
	}
	return nil, last
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A stale workload cannot acquire another execution's rights if its old
	// proxy port is reused. Credentials are independent even for one Network.
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(p.authorization())) != 1 {
		w.Header().Set("Proxy-Authenticate", `Basic realm="world"`)
		http.Error(w, "execution proxy credential required", http.StatusProxyAuthRequired)
		return
	}
	address := r.URL.Host
	if r.Method == http.MethodConnect {
		address = r.Host
	} else {
		if r.URL.Scheme != "http" || r.URL.User != nil || r.URL.Host == "" || r.Host != r.URL.Host {
			http.Error(w, "absolute HTTP URL required", http.StatusBadRequest)
			return
		}
		if r.URL.Port() == "" {
			address = net.JoinHostPort(r.URL.Hostname(), "80")
		}
	}
	if _, ok := p.permitted(address); !ok {
		http.Error(w, "destination denied by Network policy", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		p.tunnel(w, r, address)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	stripHopHeaders(out.Header)
	out.Close = true
	response, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	stripHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, address string) {
	upstream, err := p.dial(r.Context(), "tcp", address)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	client, buffered, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = buffered.Flush(); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, buffered)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	<-done
}

func stripHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(token))
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}

type trackedConn struct {
	net.Conn
	proxy *Proxy
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.proxy.mu.Lock()
	delete(c.proxy.conns, c)
	c.proxy.mu.Unlock()
	return err
}

func (p *Proxy) track(c net.Conn) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return nil, net.ErrClosed
	}
	t := &trackedConn{Conn: c, proxy: p}
	p.conns[t] = struct{}{}
	return t, nil
}

type trackedListener struct {
	net.Listener
	proxy *Proxy
}

func (l trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.proxy.track(c)
}
