package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Policy is trusted operator input, not a policy an untrusted workload may select.
// An empty Allow list means offline. Rules grant a TCP destination, not a URL.
type Policy struct {
	NetworkID string     `json:"network_id"`
	Allow     []Endpoint `json:"allow"`
}

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func ReadPolicy(r io.Reader) (Policy, error) {
	var p Policy
	data, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil {
		return p, err
	}
	if len(data) > 65536 {
		return p, fmt.Errorf("policy exceeds 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, fmt.Errorf("decode policy: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return p, fmt.Errorf("policy must contain exactly one JSON object")
	}
	return p, p.Validate()
}

func (p Policy) Validate() error {
	if p.NetworkID == "" || len(p.NetworkID) > 128 || strings.ContainsAny(p.NetworkID, "\x00\r\n") {
		return fmt.Errorf("network_id must be nonempty and at most 128 bytes")
	}
	if len(p.Allow) > 256 {
		return fmt.Errorf("at most 256 destinations are allowed")
	}
	for _, e := range p.Allow {
		if _, err := canonicalHost(e.Host); err != nil {
			return err
		}
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("invalid destination port %d", e.Port)
		}
	}
	return nil
}

func canonicalHost(host string) (string, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return "", fmt.Errorf("unsupported destination address %q", host)
		}
		return a.Unmap().String(), nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) == 0 || len(host) > 253 {
		return "", fmt.Errorf("invalid destination host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid destination host %q", host)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid destination host %q", host)
			}
		}
	}
	return host, nil
}

func authority(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
