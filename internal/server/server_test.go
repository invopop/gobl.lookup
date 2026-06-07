package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.lookup/internal/identity"
	"github.com/invopop/gobl.lookup/internal/registry"
	"github.com/invopop/gobl.lookup/internal/server"
)

// mockFetcher serves a map[url]bytes. Used by the goblnet.Client
// the server uses to verify incoming envelopes.
type mockFetcher struct {
	data map[string][]byte
}

func (m *mockFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	if d, ok := m.data[url]; ok {
		return d, nil
	}
	return nil, goblnet.ErrFetchFailed
}

// mockSender records send attempts. By default it succeeds; set
// `err` to make Send fail.
type mockSender struct {
	mu   sync.Mutex
	sent []sentEnvelope
	err  error
}

type sentEnvelope struct {
	to  goblnet.Address
	env *gobl.Envelope
}

func (m *mockSender) Send(_ context.Context, addr goblnet.Address, env *gobl.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentEnvelope{to: addr, env: env})
	return m.err
}

func (m *mockSender) records() []sentEnvelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sentEnvelope, len(m.sent))
	copy(out, m.sent)
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// fixture spins up a lookup identity in a tempdir + a registry +
// a mock fetcher that serves the subject's published key. Returns
// everything the inbox test needs to POST a registration.
type fixture struct {
	t        *testing.T
	lookup   *identity.Identity
	subject  *dsig.PrivateKey
	subAddr  goblnet.Address
	registry *registry.MemoryStore
	sender   *mockSender
	mux      http.Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	lookup, err := identity.Init(identity.ScaffoldOptions{
		Domain:    goblnet.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)

	subKey := dsig.NewES256Key()
	pub, _ := json.Marshal(subKey.Public())

	subAddr := goblnet.Address("alice.example")
	fetcher := &mockFetcher{data: map[string][]byte{
		subAddr.KeyURL(subKey.ID()): pub,
	}}
	client := goblnet.NewClient(goblnet.WithFetcher(fetcher))
	reg := registry.NewMemoryStore()
	send := &mockSender{}

	mux := server.NewMux(server.Deps{
		Identity:      lookup,
		Registry:      reg,
		Client:        client,
		Sender:        send,
		Logger:        discardLogger(),
		PublicBaseURL: "https://lookup.example",
	})
	return &fixture{t: t, lookup: lookup, subject: subKey, subAddr: subAddr, registry: reg, sender: send, mux: mux}
}

// signPartyEnvelope builds a fresh signed envelope from subject
// with the given iss/aud.
func (f *fixture) signPartyEnvelope(iss, aud cbc.URI) *gobl.Envelope {
	f.t.Helper()
	party := &org.Party{
		Name:      "Alice",
		Endpoints: []*org.Endpoint{{URI: f.subAddr.URI()}},
	}
	env, err := gobl.Envelop(party)
	require.NoError(f.t, err)
	require.NoError(f.t, env.Sign(f.subject, iss, aud))
	return env
}

// waitForDelivery spins until the mock sender records something
// or the deadline expires. The inbox handler delivers async via a
// goroutine so the POST returns immediately.
func (f *fixture) waitForDelivery(d time.Duration) []sentEnvelope {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if got := f.sender.records(); len(got) > 0 {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return f.sender.records()
}

func (f *fixture) post(path string, body []byte) *http.Response {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func (f *fixture) get(path string) *http.Response {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func TestInboxAcceptsRegistration(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.URI(), f.lookup.URI())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Record persisted with the Authority countersignature.
	rec, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, registry.StatusCountersigned, rec.Status)
	assert.Equal(t, head.ScopeRegistered, rec.Scope)
	require.NotNil(t, rec.CountersignedEnvelope)
	require.Len(t, rec.CountersignedEnvelope.Signatures, 2,
		"original subject signature + lookup countersignature")

	// Inspect the Authority signature's payload.
	authSig := rec.CountersignedEnvelope.Signatures[1]
	p, err := head.SignedPayload(authSig)
	require.NoError(t, err)
	assert.Equal(t, f.lookup.URI(), p.Iss)
	assert.Equal(t, f.subAddr.URI(), p.Aud)
	assert.Equal(t, head.ScopeRegistered, p.Scope)

	// Discovery link stamped on the (mutable) header.
	require.NotEmpty(t, rec.CountersignedEnvelope.Head.Links)
	link := rec.CountersignedEnvelope.Head.Links[0]
	assert.Equal(t, cbc.Key("authority"), link.Category)
	assert.Equal(t, cbc.Key("lookup"), link.Key)
	assert.Contains(t, link.URL, env.Head.UUID.String())

	// Delivery goroutine eventually posts to the subject's inbox.
	sent := f.waitForDelivery(2 * time.Second)
	require.Len(t, sent, 1)
	assert.Equal(t, f.subAddr, sent[0].to)
	assert.Equal(t, env.Head.UUID, sent[0].env.Head.UUID)
}

func TestInboxRejectsMissingAud(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.URI(), "")
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestInboxRejectsWrongAud(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.URI(), goblnet.Address("someone.else").URI())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestInboxRejectsNonPartyDocument(t *testing.T) {
	f := newFixture(t)
	// Sign a note message instead of a party.
	msg := &org.Inbox{Code: "x"} // pick any non-Party doc registered in core
	env, err := gobl.Envelop(msg)
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject, f.subAddr.URI(), f.lookup.URI()))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestInboxRejectsMalformedJSON(t *testing.T) {
	f := newFixture(t)
	resp := f.post(goblnet.InboxPath, []byte("not json"))
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestInboxRejectsUnknownSigner(t *testing.T) {
	f := newFixture(t)
	// Sign with a brand-new key not served by the fetcher.
	other := dsig.NewES256Key()
	party := &org.Party{
		Name:      "Mallory",
		Endpoints: []*org.Endpoint{{URI: goblnet.Address("mallory.example").URI()}},
	}
	env, err := gobl.Envelop(party)
	require.NoError(t, err)
	require.NoError(t, env.Sign(other, goblnet.Address("mallory.example").URI(), f.lookup.URI()))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestReRegistrationDropsScopeToRegistered(t *testing.T) {
	f := newFixture(t)
	// First registration.
	env1 := f.signPartyEnvelope(f.subAddr.URI(), f.lookup.URI())
	body1, _ := json.Marshal(env1)
	f.post(goblnet.InboxPath, body1).Body.Close() //nolint:errcheck

	// Manually bump scope to verified to simulate the admin path.
	rec, _ := f.registry.Get(context.Background(), f.subAddr)
	rec.Scope = head.ScopeVerified
	now := time.Now().UTC()
	rec.VerifiedAt = &now
	_, err := f.registry.Put(context.Background(), rec)
	require.NoError(t, err)

	// Re-register: scope must drop back to registered.
	env2 := f.signPartyEnvelope(f.subAddr.URI(), f.lookup.URI())
	body2, _ := json.Marshal(env2)
	f.post(goblnet.InboxPath, body2).Body.Close() //nolint:errcheck

	rec2, _ := f.registry.Get(context.Background(), f.subAddr)
	assert.Equal(t, head.ScopeRegistered, rec2.Scope)
	assert.Nil(t, rec2.VerifiedAt, "verified timestamp cleared on re-registration")
}

func TestPartiesLookupByUUID(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.URI(), f.lookup.URI())
	body, _ := json.Marshal(env)
	f.post(goblnet.InboxPath, body).Body.Close() //nolint:errcheck
	_ = f.waitForDelivery(2 * time.Second)

	resp := f.get("/parties/" + env.Head.UUID.String())
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got gobl.Envelope
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, env.Head.UUID, got.Head.UUID)
	require.Len(t, got.Signatures, 2)
}

func TestPartiesLookupByAddress(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.URI(), f.lookup.URI())
	body, _ := json.Marshal(env)
	f.post(goblnet.InboxPath, body).Body.Close() //nolint:errcheck

	resp := f.get("/parties/" + string(f.subAddr))
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPartiesLookupNotFound(t *testing.T) {
	f := newFixture(t)
	resp := f.get("/parties/nobody.example")
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestKeysEndpoint(t *testing.T) {
	f := newFixture(t)
	kid := f.lookup.PrivateKey.ID()
	resp := f.get(goblnet.KeyPath(kid))
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var pk dsig.PublicKey
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pk))
	assert.Equal(t, kid, pk.ID())
}

func TestKeysEndpoint404(t *testing.T) {
	f := newFixture(t)
	resp := f.get(goblnet.KeyPath("missing-kid"))
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestJWKSEndpoint(t *testing.T) {
	f := newFixture(t)
	resp := f.get(goblnet.JWKSPath)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
	require.Len(t, set.Keys, 1)
}

func TestWhoExchange(t *testing.T) {
	f := newFixture(t)
	// Caller posts a signed envelope; we don't strictly need it to
	// be a party for /who — any document works.
	party := &org.Party{Name: "Alice", Endpoints: []*org.Endpoint{{URI: f.subAddr.URI()}}}
	env, err := gobl.Envelop(party)
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject, f.subAddr.URI(), f.lookup.URI()))
	body, _ := json.Marshal(env)

	resp := f.post(goblnet.WhoPath, body)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got gobl.Envelope
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Signatures, 1)
	p, err := head.SignedPayload(got.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, f.lookup.URI(), p.Iss)
	assert.Equal(t, f.subAddr.URI(), p.Aud)
}

func TestHealth(t *testing.T) {
	f := newFixture(t)
	resp := f.get("/healthz")
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAllowListBlocksUnknownSender(t *testing.T) {
	dir := t.TempDir()
	lookup, err := identity.Init(identity.ScaffoldOptions{
		Domain:    goblnet.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	// Add an allow.json that excludes alice.example.
	lookup.Allow = []goblnet.Address{"bob.example"}

	subKey := dsig.NewES256Key()
	pub, _ := json.Marshal(subKey.Public())
	subAddr := goblnet.Address("alice.example")
	client := goblnet.NewClient(goblnet.WithFetcher(&mockFetcher{
		data: map[string][]byte{subAddr.KeyURL(subKey.ID()): pub},
	}))
	mux := server.NewMux(server.Deps{
		Identity: lookup,
		Registry: registry.NewMemoryStore(),
		Client:   client,
		Sender:   &mockSender{},
		Logger:   discardLogger(),
	})

	party := &org.Party{Name: "Alice", Endpoints: []*org.Endpoint{{URI: subAddr.URI()}}}
	env, err := gobl.Envelop(party)
	require.NoError(t, err)
	require.NoError(t, env.Sign(subKey, subAddr.URI(), lookup.URI()))
	body, _ := json.Marshal(env)

	req := httptest.NewRequest(http.MethodPost, goblnet.InboxPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Result().StatusCode)
}
