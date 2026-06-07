// Package delivery POSTs a signed envelope to a remote GOBL Net
// inbox (e.g. the sender's own /.well-known/gobl/inbox) after the
// lookup has countersigned it. The transport reuses gobl/net's
// rules: HTTPS only, refuse to dial loopback / private / link-local
// / multicast / unspecified addresses (SSRF defense). The check is
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

// Defaults mirror gobl.dev's `gobl net send` and gobl/net's
// HTTPFetcher so the wire behaviour is consistent.
const (
	defaultTimeout = 10 * time.Second
	dialTimeout    = 5 * time.Second
	maxBodySize    = 1 << 20 // 1 MiB
)

// Errors returned by Sender.Send.
var (
	// ErrInboxRejected matches gobl/net's sentinel — the remote
	// /inbox returned anything other than 202.
	ErrInboxRejected = net.ErrInboxRejected
	// ErrSendFailed wraps transport / encoding errors during send.
	ErrSendFailed = errors.New("delivery: send failed")
)

// Sender posts envelopes to remote GOBL Net inboxes. Construct
// with NewSender; the zero value is not usable.
type Sender struct {
	client *http.Client
}

// NewSender returns a Sender whose transport refuses to dial any
// resolved IP that is loopback, private, link-local, multicast, or
// unspecified. allowLoopback bypasses the guard; intended for
// tests that talk to httptest servers bound to 127.0.0.1. There is
// no public wrapper that exposes allowLoopback.
func NewSender() *Sender { return newSender(false) }

func newSender(allowLoopback bool) *Sender {
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
	return &Sender{
		client: &http.Client{
			Timeout:   defaultTimeout,
			Transport: transport,
		},
	}
}

// Send posts env to the remote address's /inbox URL. The host
// (derived from net.Address.InboxURL) MUST resolve to a public IP
// (see SSRF defense above).
func (s *Sender) Send(ctx context.Context, addr net.Address, env *gobl.Envelope) error {
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
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("%w: HTTP %d from %s", ErrInboxRejected, resp.StatusCode, url)
	}
	return nil
}

// safeDialContext is the DialContext used by the default Sender's
// transport. Duplicates gobl/net/client.go's logic — see the
// package doc for why.
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
	d := &stdnet.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, network, stdnet.JoinHostPort(host, port))
}

// isPublicIP rejects any loopback, private (RFC 1918 / RFC 6598),
// link-local, multicast, or unspecified IP. Mirrors the helper in
// gobl/net/client.go.
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
	return true
}
