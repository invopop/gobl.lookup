// Package delivery POSTs a signed envelope to a remote GOBL Net
// inbox (e.g. the sender's own /.well-known/gobl/inbox) after the
// lookup has countersigned it. The transport follows gobl/net's
// rules (spec §9): it refuses to dial addresses that are not globally
// reachable (SSRF defense) and follows no redirects. The checks are
// inlined here rather than imported from gobl/net (the helpers are
// unexported there); the canonical implementation lives in
// gobl/net/client.go.
package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	stdnet "net"
	"net/http"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/net"
)

// dialTimeout bounds connection establishment (dial + TLS handshake).
// The overall request deadline is governed by the caller's context, not
// a fixed http.Client.Timeout, so it stays consistent with the domain's
// delivery timeout.
const dialTimeout = 5 * time.Second

// fallbackDialTimeout bounds a dial to a resolved address with others
// left to try.
const fallbackDialTimeout = 2 * time.Second

// Errors returned by Send.
var (
	// ErrInboxRejected matches gobl/net's sentinel — the remote
	// /inbox definitively rejected the envelope (a non-429 4xx);
	// retrying will not help.
	ErrInboxRejected = net.ErrInboxRejected
	// ErrUnavailable matches gobl/net's sentinel — the remote /inbox
	// could not be reached or answered 429/5xx; the delivery should
	// be retried.
	ErrUnavailable = net.ErrUnavailable
	// ErrSendFailed wraps input / encoding errors during send.
	ErrSendFailed = errors.New("delivery: send failed")
)

// Sender posts a countersigned envelope to a remote GOBL Net inbox.
// The domain depends on this interface; HTTPSender is the production
// implementation and tests substitute their own.
type Sender interface {
	Send(ctx context.Context, addr net.Address, env *gobl.Envelope) error
}

// HTTPSender is the HTTP implementation of Sender. Construct with New;
// the zero value is not usable. Requests carry no request token: an
// inbox delivery is authenticated by the envelope's own signature
// (spec §6).
type HTTPSender struct {
	client *http.Client
}

// New returns an HTTPSender whose transport refuses to dial any
// resolved IP that is not globally reachable (see isPublicIP) and
// follows no redirects.
func New() *HTTPSender {
	return newSender(false)
}

// newSender builds an HTTPSender; allowLoopback bypasses the SSRF
// guard, intended only for tests that talk to httptest servers bound
// to 127.0.0.1. There is no public wrapper that exposes it.
func newSender(allowLoopback bool) *HTTPSender {
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if !allowLoopback {
		transport.DialContext = safeDialContext
	}
	return &HTTPSender{
		// No fixed Timeout: the per-request deadline comes from the
		// caller's context (see Send), keeping it in step with the
		// domain's delivery timeout.
		client: &http.Client{
			Transport: transport,
			// A redirect could move the delivery to plain HTTP.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Send posts env to the remote address's /inbox URL. The host
// (derived from net.Address.InboxURL) MUST resolve to a public IP
// (see SSRF defense above).
func (s *HTTPSender) Send(ctx context.Context, addr net.Address, env *gobl.Envelope) error {
	if env == nil {
		return fmt.Errorf("%w: envelope is nil", ErrSendFailed)
	}
	if err := addr.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("%w: marshal envelope: %v", ErrSendFailed, err)
	}
	url := addr.InboxURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrSendFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		// Transport failures are transient: the async delivery loop
		// retries them, unlike definitive inbox rejections.
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	switch {
	case resp.StatusCode == http.StatusAccepted:
		return nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("%w: HTTP %d from %s: redirects are not followed", ErrInboxRejected, resp.StatusCode, url)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("%w: HTTP %d from %s", ErrUnavailable, resp.StatusCode, url)
	default:
		return fmt.Errorf("%w: HTTP %d from %s", ErrInboxRejected, resp.StatusCode, url)
	}
}

// safeDialContext is the DialContext used by the default HTTPSender's
// transport. Duplicates gobl/net/client.go's logic — see the package
// doc for why.
func safeDialContext(ctx context.Context, network, addr string) (stdnet.Conn, error) {
	host, port, err := stdnet.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := stdnet.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSendFailed, err)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return nil, fmt.Errorf("%w: refusing to dial non-public address %s (%s)", ErrSendFailed, host, ip)
		}
	}
	// Dial the IPs we just vetted rather than re-resolving the host at
	// connect time: a second resolution could return a different, private
	// address and slip past the check (DNS rebinding / TOCTOU).
	// Each address but the last gets fallbackDialTimeout, so one that
	// drops packets does not hold up the next.
	var lastErr error
	for i, ip := range ips {
		d := &stdnet.Dialer{Timeout: dialTimeout}
		if i < len(ips)-1 {
			d.Timeout = fallbackDialTimeout
		}
		conn, err := d.DialContext(ctx, network, stdnet.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no addresses for %s", ErrSendFailed, host)
	}
	return nil, lastErr
}

// isPublicIP reports whether ip is globally reachable: not loopback,
// private, link-local, multicast or unspecified, and in none of the IANA
// special-purpose ranges that are not globally reachable, nor in a
// translation range (NAT64, 6to4, Teredo) that can reach them. Mirrors
// the helper in gobl/net/client.go.
func isPublicIP(ip stdnet.IP) bool {
	if ip == nil {
		return false
	}
	switch {
	case ip.IsLoopback(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsUnspecified(),
		ip.IsMulticast():
		return false
	}
	for _, n := range nonPublicNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// nonPublicNets lists the ranges the net.IP methods miss, from the IANA
// IPv4 and IPv6 special-purpose address registries.
var nonPublicNets = func() []*stdnet.IPNet {
	cidrs := []string{
		"0.0.0.0/8",       // this network (RFC 791)
		"100.64.0.0/10",   // shared address space (RFC 6598)
		"192.0.0.0/24",    // IETF protocol assignments (RFC 6890)
		"192.0.2.0/24",    // documentation, TEST-NET-1 (RFC 5737)
		"192.88.99.0/24",  // 6to4 relay anycast (RFC 7526)
		"198.18.0.0/15",   // benchmarking (RFC 2544)
		"198.51.100.0/24", // documentation, TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",  // documentation, TEST-NET-3 (RFC 5737)
		"240.0.0.0/4",     // reserved, and broadcast (RFC 1112)
		"64:ff9b::/96",    // NAT64 (RFC 6052)
		"64:ff9b:1::/48",  // local-use NAT64 (RFC 8215)
		"100::/64",        // discard-only (RFC 6666)
		"2001::/23",       // IETF protocol assignments, including Teredo (RFC 2928)
		"2001:db8::/32",   // documentation (RFC 3849)
		"2002::/16",       // 6to4 (RFC 3056)
		"3fff::/20",       // documentation (RFC 9637)
		"5f00::/16",       // segment routing SIDs (RFC 9602)
	}
	nets := make([]*stdnet.IPNet, len(cidrs))
	for i, c := range cidrs {
		_, n, err := stdnet.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		nets[i] = n
	}
	return nets
}()
