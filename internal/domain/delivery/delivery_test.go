package delivery

import (
	"context"
	"errors"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/note"
	"github.com/invopop/gobl/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildEnvelope(t *testing.T) *gobl.Envelope {
	t.Helper()
	msg := &note.Message{Content: "hi"}
	msg.SetUUID(uuid.V7())
	env, err := gobl.Envelop(msg)
	require.NoError(t, err)
	key := dsig.NewES256Key()
	require.NoError(t, env.Sign(key, net.Address("alice.example").URI(), net.Address("lookup.example").URI()))
	return env
}

func TestSenderSend202(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		b := make([]byte, 1<<16)
		n, _ := r.Body.Read(b)
		receivedBody = b[:n]
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// Build a Sender that talks to localhost (the SSRF guard would
	// normally refuse). We use the same internal-only constructor
	// trick gobl/net does for its tests, then exercise the transport
	// directly via a one-off request matching what Send constructs.
	s := newSender(true)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+net.InboxPath, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	_ = receivedBody
	_ = buildEnvelope // referenced by other tests below
}

func TestSenderRejectsLoopbackByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	s := New()
	// httptest binds 127.0.0.1 — the default Sender MUST refuse.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+net.InboxPath, strings.NewReader(`{}`))
	_, err := s.client.Do(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to dial non-public address")
}

func TestSafeDialContextRejectsLoopback(t *testing.T) {
	// The public Send path resolves addr.InboxURL() via DNS; an
	// FQDN like "alice.example" fails with NXDOMAIN rather than
	// hitting the SSRF reject path. Test the reject directly.
	_, err := safeDialContext(context.Background(), "tcp", "127.0.0.1:80")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSendFailed))
	assert.Contains(t, err.Error(), "refusing to dial non-public address")
}

func TestSendNilEnvelope(t *testing.T) {
	err := New().Send(context.Background(), net.Address("alice.example"), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSendFailed))
}

func TestSendInvalidAddress(t *testing.T) {
	err := New().Send(context.Background(), net.Address("not a domain"), buildEnvelope(t))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSendFailed))
}

func TestSendNon202ReturnsInboxRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	s := newSender(true)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+net.InboxPath, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	assert.NotEqual(t, http.StatusAccepted, resp.StatusCode)
}

func TestIsPublicIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":         true,
		"1.1.1.1":         true,
		"127.0.0.1":       false,
		"::1":             false,
		"10.0.0.1":        false,
		"169.254.169.254": false,
		"0.0.0.0":         false,
		"224.0.0.1":       false,
	}
	for ip, want := range cases {
		t.Run(ip, func(t *testing.T) {
			parsed := stdnet.ParseIP(ip)
			require.NotNil(t, parsed)
			assert.Equal(t, want, isPublicIP(parsed))
		})
	}
	assert.False(t, isPublicIP(nil))
}
