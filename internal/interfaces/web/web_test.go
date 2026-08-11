package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/invopop/gobl.lookup/internal/domain"
	"github.com/invopop/gobl.lookup/internal/domain/models"
	"github.com/invopop/gobl.lookup/internal/domain/repos"
	"github.com/invopop/gobl.lookup/internal/interfaces/web"
)

// mockFetcher serves a map[url]bytes, with optional per-URL errors.
// Used by the goblnet.Client the domain uses to verify incoming
// envelopes and resolve sender identities.
type mockFetcher struct {
	data map[string][]byte
	errs map[string]error
}

func (m *mockFetcher) Fetch(_ context.Context, url string, _ http.Header) ([]byte, error) {
	if err, ok := m.errs[url]; ok {
		return nil, err
	}
	if d, ok := m.data[url]; ok {
		return d, nil
	}
	return nil, goblnet.ErrFetchFailed
}

func (m *mockFetcher) Post(_ context.Context, _ string, _ []byte, _ http.Header) error {
	return goblnet.ErrFetchFailed
}

// mockSender records send attempts. By default it succeeds; set `err`
// to make Send fail.
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

// fixture spins up a lookup identity in a tempdir + an in-memory
// registry + a mock fetcher that serves the subject's published key
// and its GET /who identity. Returns everything the inbox test needs
// to POST a registration.
type fixture struct {
	t         *testing.T
	lookup    *models.Identity
	subject   *dsig.PrivateKey
	subAddr   goblnet.Address
	verifier  *dsig.PrivateKey
	verifAddr goblnet.Address
	fetcher   *mockFetcher
	registry  *repos.MemoryRegistrations
	sender    *mockSender
	mux       http.Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	lookup, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    goblnet.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)

	subKey := dsig.NewES256Key()
	pub, _ := json.Marshal(subKey.Public())

	subAddr := goblnet.Address("alice.example")
	verifKey := dsig.NewES256Key()
	verifPub, _ := json.Marshal(verifKey.Public())
	verifAddr := goblnet.Address("verify.example")
	fetcher := &mockFetcher{
		data: map[string][]byte{
			subAddr.KeyURL(subKey.ID()):     pub,
			verifAddr.KeyURL(verifKey.ID()): verifPub,
		},
		errs: map[string]error{},
	}
	client := goblnet.NewClient(goblnet.WithFetcher(fetcher))
	reg := repos.NewMemoryRegistrations()
	send := &mockSender{}

	setup := domain.New(domain.Deps{
		Identity:      lookup,
		Registrations: reg,
		Client:        client,
		Sender:        send,
		Verifiers:     []goblnet.Address{verifAddr},
		PublicBaseURL: "https://lookup.example",
		Logger:        discardLogger(),
	})
	mux := web.NewMux(setup, discardLogger())
	f := &fixture{t: t, lookup: lookup, subject: subKey, subAddr: subAddr, verifier: verifKey, verifAddr: verifAddr, fetcher: fetcher, registry: reg, sender: send, mux: mux}
	// The registration flow resolves the sender's own GET /who, so the
	// fixture serves a self-signed identity for the subject by default.
	who, _ := json.Marshal(f.signPartyEnvelope(subAddr.String(), ""))
	fetcher.data[subAddr.WhoURL()] = who
	return f
}

// signPartyEnvelope builds a fresh signed envelope from subject with
// the given iss/aud.
func (f *fixture) signPartyEnvelope(iss, aud string) *gobl.Envelope {
	f.t.Helper()
	party := &org.Party{
		Name:      "Alice",
		Endpoints: []*org.Endpoint{{URI: f.subAddr.URI()}},
	}
	env, err := gobl.Envelop(party)
	require.NoError(f.t, err)
	opts := []head.SignOption{head.WithIssuer(iss)}
	if aud != "" {
		opts = append(opts, head.WithAudience(aud))
	}
	require.NoError(f.t, env.Sign(f.subject, opts...))
	return env
}

// waitForDelivery spins until the mock sender records something or the
// deadline expires. The inbox handler delivers async so the POST
// returns immediately.
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

// bearer mints a request token from the subject for the lookup, as
// any conforming client would attach to a who or inbox request.
func (f *fixture) bearer() string {
	f.t.Helper()
	token, err := goblnet.NewToken(f.subject, f.subAddr, f.lookup.Address(), 0)
	require.NoError(f.t, err)
	return "Bearer " + token
}

func (f *fixture) post(path string, body []byte) *http.Response {
	return f.do(http.MethodPost, path, body, f.bearer())
}

func (f *fixture) get(path string) *http.Response {
	return f.do(http.MethodGet, path, nil, f.bearer())
}

// do performs a request with an explicit Authorization value; empty
// auth sends the request bare.
func (f *fixture) do(method, path string, body []byte, auth string) *http.Response {
	f.t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec.Result()
}

func TestInboxAcceptsRegistration(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Record persisted with the Authority countersignature. Delivery
	// happens asynchronously and the mock sender is instant, so the
	// record may already have advanced from countersigned to
	// delivered by the time we read it.
	rec, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Contains(t, []models.Status{models.StatusCountersigned, models.StatusDelivered}, rec.Status)
	assert.Empty(t, rec.Verifier, "initial registration carries no verifier")
	require.NotNil(t, rec.CountersignedEnvelope)
	require.Len(t, rec.CountersignedEnvelope.Signatures, 2,
		"original subject signature + lookup countersignature")

	// Inspect the Authority signature's payload.
	authSig := rec.CountersignedEnvelope.Signatures[1]
	p, err := head.SignedPayload(authSig)
	require.NoError(t, err)
	assert.Equal(t, f.lookup.Address().String(), p.Iss)
	assert.Equal(t, f.subAddr.String(), p.Aud)
	assert.Empty(t, p.Verifier, "initial countersignature carries no verifier claim")

	// Discovery link stamped on the (mutable) header.
	require.NotEmpty(t, rec.CountersignedEnvelope.Head.Links)
	link := rec.CountersignedEnvelope.Head.Links[0]
	assert.Equal(t, head.LinkCategoryKeyVerification, link.Category)
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
	env := f.signPartyEnvelope(f.subAddr.String(), "")
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestInboxRejectsWrongAud(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.String(), "someone.else")
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestInboxRejectsNonPartyDocument(t *testing.T) {
	f := newFixture(t)
	// Sign a non-party document instead of a party.
	msg := &org.Inbox{Code: "x"}
	env, err := gobl.Envelop(msg)
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.lookup.Address().String())))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestInboxRejectsOversizedBody(t *testing.T) {
	f := newFixture(t)
	// Larger than the handler's 1 MiB cap → rejected, not truncated.
	resp := f.post(goblnet.InboxPath, bytes.Repeat([]byte("a"), (1<<20)+1024))
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
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
	require.NoError(t, env.Sign(other,
		head.WithIssuer("mallory.example"),
		head.WithAudience(f.lookup.Address().String())))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestReRegistrationDropsVerifier(t *testing.T) {
	f := newFixture(t)
	// First registration.
	env1 := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body1, _ := json.Marshal(env1)
	f.post(goblnet.InboxPath, body1).Body.Close() //nolint:errcheck

	// Manually mark as verified to simulate the admin path.
	rec, _ := f.registry.Get(context.Background(), f.subAddr)
	rec.Verifier = "kyc.example"
	now := time.Now().UTC()
	rec.VerifiedAt = &now
	err := f.registry.Put(context.Background(), rec)
	require.NoError(t, err)

	// Re-register: the verifier must be dropped — prior KYC no
	// longer applies to changed party data.
	env2 := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body2, _ := json.Marshal(env2)
	f.post(goblnet.InboxPath, body2).Body.Close() //nolint:errcheck

	rec2, _ := f.registry.Get(context.Background(), f.subAddr)
	assert.Empty(t, rec2.Verifier)
	assert.Nil(t, rec2.VerifiedAt, "verified timestamp cleared on re-registration")
}

// signSameParty envelopes and signs the given party without altering
// it, so repeated calls produce envelopes with identical digests —
// the renewal case.
func (f *fixture) signSameParty(party *org.Party) *gobl.Envelope {
	f.t.Helper()
	env, err := gobl.Envelop(party)
	require.NoError(f.t, err)
	require.NoError(f.t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.lookup.Address().String())))
	return env
}

func TestRenewalPreservesVerifier(t *testing.T) {
	f := newFixture(t)
	party := &org.Party{
		Name:      "Alice",
		Endpoints: []*org.Endpoint{{URI: f.subAddr.URI()}},
	}
	env1 := f.signSameParty(party) // assigns the party's UUID
	body1, _ := json.Marshal(env1)
	f.post(goblnet.InboxPath, body1).Body.Close() //nolint:errcheck

	// Simulate out-of-band KYC.
	rec, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	rec.Verifier = "kyc.example"
	now := time.Now().UTC()
	rec.VerifiedAt = &now
	require.NoError(t, f.registry.Put(context.Background(), rec))

	// Renew with the unchanged party document (same digest).
	env2 := f.signSameParty(party)
	body2, _ := json.Marshal(env2)
	resp := f.post(goblnet.InboxPath, body2)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	rec2, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, goblnet.Address("kyc.example"), rec2.Verifier, "renewal keeps the verifier")
	assert.NotNil(t, rec2.VerifiedAt, "renewal keeps the verification timestamp")

	// The renewal countersignature asserts the preserved verifier and
	// a fresh ~90 day expiry.
	sigs := rec2.CountersignedEnvelope.Signatures
	p, err := head.SignedPayload(sigs[len(sigs)-1])
	require.NoError(t, err)
	assert.Equal(t, "kyc.example", p.Verifier)
	assert.Greater(t, p.ExpiresAt, time.Now().Add(89*24*time.Hour).Unix())
	assert.Less(t, p.ExpiresAt, time.Now().Add(91*24*time.Hour).Unix())
}

func TestPartiesLookupByUUID(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
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
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
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

func TestWhoGet(t *testing.T) {
	f := newFixture(t)
	resp := f.get(goblnet.WhoPath)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "private, max-age=300", resp.Header.Get("Cache-Control"), "authorized response must not land in shared caches")

	var got gobl.Envelope
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Signatures, 1)
	p, err := head.SignedPayload(got.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, f.lookup.Address().String(), p.Iss)
	assert.Empty(t, p.Aud, "GET who response is not bound to a caller")
}

func TestRequestAuth(t *testing.T) {
	f := newFixture(t)

	t.Run("who without a token is rejected", func(t *testing.T) {
		resp := f.do(http.MethodGet, goblnet.WhoPath, nil, "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("inbox without a token is rejected", func(t *testing.T) {
		env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
		body, _ := json.Marshal(env)
		resp := f.do(http.MethodPost, goblnet.InboxPath, body, "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("non-bearer scheme is rejected", func(t *testing.T) {
		resp := f.do(http.MethodGet, goblnet.WhoPath, nil, "Basic dXNlcjpwdw==")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("token bound to another audience is rejected", func(t *testing.T) {
		token, err := goblnet.NewToken(f.subject, f.subAddr, "other.example", 0)
		require.NoError(t, err)
		resp := f.do(http.MethodGet, goblnet.WhoPath, nil, "Bearer "+token)
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("token from an unresolvable issuer is rejected", func(t *testing.T) {
		other := dsig.NewES256Key()
		token, err := goblnet.NewToken(other, "unknown.example", f.lookup.Address(), 0)
		require.NoError(t, err)
		resp := f.do(http.MethodGet, goblnet.WhoPath, nil, "Bearer "+token)
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("keys and parties stay open", func(t *testing.T) {
		resp := f.do(http.MethodGet, goblnet.KeyPath(f.lookup.PrivateKey.ID()), nil, "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestInboxRejectsPendingWho(t *testing.T) {
	// A registrant deferring its own /who disclosure (202) cannot be
	// confirmed as a sending participant.
	f := newFixture(t)
	f.fetcher.errs[f.subAddr.WhoURL()] = goblnet.ErrPending

	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestHealth(t *testing.T) {
	f := newFixture(t)
	resp := f.get("/healthz")
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestInboxRejectsSenderWithoutWho(t *testing.T) {
	f := newFixture(t)
	// The sender's key resolves, but its GET /who does not.
	delete(f.fetcher.data, f.subAddr.WhoURL())

	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestInboxRejectsReceiveOnlySender(t *testing.T) {
	f := newFixture(t)
	// A 204 from the sender's who marks a receive-only account, which
	// cannot register as a sender.
	delete(f.fetcher.data, f.subAddr.WhoURL())
	f.fetcher.errs[f.subAddr.WhoURL()] = goblnet.ErrNoContent

	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRequestAuthUnavailable(t *testing.T) {
	// The requester's key endpoint is unreachable: the lookup answers
	// 503 so the caller retries, not a definitive 401.
	f := newFixture(t)
	f.fetcher.errs[f.subAddr.KeyURL(f.subject.ID())] = fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable)

	resp := f.get(goblnet.WhoPath)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestInboxWhoUnavailable(t *testing.T) {
	// A transient outage resolving the sender's who must answer 503 —
	// a 4xx would make the sender stop retrying its registration.
	f := newFixture(t)
	f.fetcher.errs[f.subAddr.WhoURL()] = fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable)

	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// counterSignAsVerifier stamps the fixture verifier's countersignature
// onto env, as a provider would after completing its checks.
func (f *fixture) counterSignAsVerifier(env *gobl.Envelope) {
	f.t.Helper()
	require.NoError(f.t, env.Sign(f.verifier,
		head.WithIssuer(f.verifAddr.String()),
		head.WithAudience(f.subAddr.String()),
		head.WithExpiration(time.Now().Add(365*24*time.Hour))))
}

func TestAutoVerifyOnRegistration(t *testing.T) {
	// A registration arriving with an accepted provider's
	// countersignature is verified from the start: the lookup's own
	// countersignature names the verifier without operator action.
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	f.counterSignAsVerifier(env)
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	rec, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, f.verifAddr, rec.Verifier)
	assert.NotNil(t, rec.VerifiedAt)

	// The lookup countersignature carries the verifier claim.
	sigs := rec.CountersignedEnvelope.Signatures
	p, err := head.SignedPayload(sigs[len(sigs)-1])
	require.NoError(t, err)
	assert.Equal(t, f.verifAddr.String(), p.Verifier)
}

func TestAutoVerifyRejectsForgedCountersignature(t *testing.T) {
	// A countersignature claiming the provider's address but made with
	// a different key must not be named: consumers would reject it.
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	forged := dsig.NewES256Key()
	require.NoError(t, env.Sign(forged,
		head.WithIssuer(f.verifAddr.String()),
		head.WithAudience(f.subAddr.String())))
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusAccepted, resp.StatusCode, "registration proceeds unverified")

	rec, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Empty(t, rec.Verifier)
	assert.Nil(t, rec.VerifiedAt)
}

func TestVerifyDerivesFromStoredEnvelope(t *testing.T) {
	// A provider countersignature received while the provider was not
	// yet on the accepted list is picked up later by the verify
	// command — the recovery path.
	f := newFixture(t)

	// A parallel setup with no accepted verifiers registers the party
	// with the countersignature aboard but unverified.
	bare := domain.New(domain.Deps{
		Identity:      f.lookup,
		Registrations: f.registry,
		Client:        goblnet.NewClient(goblnet.WithFetcher(f.fetcher)),
		Sender:        f.sender,
		PublicBaseURL: "https://lookup.example",
		Logger:        discardLogger(),
	})
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	f.counterSignAsVerifier(env)
	_, err := bare.Registrations().Register(context.Background(), env)
	require.NoError(t, err)
	// Let the async delivery goroutine finish its Put before Verify
	// reads and rewrites the record.
	require.NotEmpty(t, f.waitForDelivery(2*time.Second))
	rec, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	require.Empty(t, rec.Verifier)

	// The fixture setup accepts verify.example: Verify derives it.
	f2 := domain.New(domain.Deps{
		Identity:      f.lookup,
		Registrations: f.registry,
		Client:        goblnet.NewClient(goblnet.WithFetcher(f.fetcher)),
		Sender:        f.sender,
		Verifiers:     []goblnet.Address{f.verifAddr},
		PublicBaseURL: "https://lookup.example",
		Logger:        discardLogger(),
	})
	rec, err = f2.Registrations().Verify(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, f.verifAddr, rec.Verifier)
	assert.NotNil(t, rec.VerifiedAt)
}

func TestVerifyWithoutAcceptedCountersignature(t *testing.T) {
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body, _ := json.Marshal(env)
	f.post(goblnet.InboxPath, body).Body.Close() //nolint:errcheck

	setup := domain.New(domain.Deps{
		Identity:      f.lookup,
		Registrations: f.registry,
		Client:        goblnet.NewClient(goblnet.WithFetcher(f.fetcher)),
		Sender:        f.sender,
		Verifiers:     []goblnet.Address{f.verifAddr},
		PublicBaseURL: "https://lookup.example",
		Logger:        discardLogger(),
	})
	_, err := setup.Registrations().Verify(context.Background(), f.subAddr)
	require.Error(t, err)
	assert.True(t, errors.Is(err, domain.ErrValidation))
}

// counterSignAsLookup stamps the lookup's own countersignature, as
// Register does when it endorses a registration.
func (f *fixture) counterSignAsLookup(env *gobl.Envelope) {
	f.t.Helper()
	require.NoError(f.t, env.Sign(f.lookup.PrivateKey,
		head.WithIssuer(f.lookup.Address().String()),
		head.WithAudience(f.subAddr.String()),
		head.WithExpiration(time.Now().Add(90*24*time.Hour))))
}

func TestReturnedEnvelopeFromVerifier(t *testing.T) {
	// The §5.3 round trip: the subject registered (audience-bound
	// signature), the lookup countersigned, and a verification
	// provider countersigned the exact envelope and posted it back.
	// The delivery binds through the subject's original registration
	// signature, the lookup's own countersignature still verifies,
	// and auto-verify names the provider.
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	f.counterSignAsLookup(env)
	f.counterSignAsVerifier(env)

	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	rec, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, f.verifAddr, rec.Verifier, "provider countersignature auto-verifies")
	assert.NotNil(t, rec.VerifiedAt)
}

func TestReturnedEnvelopeWithForgedOwnCountersignature(t *testing.T) {
	// A signature claiming to be this lookup's but made with another
	// key means the envelope is not what the lookup endorsed.
	f := newFixture(t)
	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	forged := dsig.NewES256Key()
	require.NoError(t, env.Sign(forged,
		head.WithIssuer(f.lookup.Address().String()),
		head.WithAudience(f.subAddr.String())))

	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestWhoServesEndorsedEnvelope(t *testing.T) {
	// The sender publishes the endorsed envelope exactly as delivered:
	// its registration signature (audience-bound) first, the lookup's
	// countersignature, and an audience-free publication signature
	// appended at serve time. The eligibility lookup must accept it —
	// this is the published shape every registered node converges on.
	f := newFixture(t)
	published := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	f.counterSignAsLookup(published)
	require.NoError(t, published.Sign(f.subject, head.WithIssuer(f.subAddr.String())))
	who, _ := json.Marshal(published)
	f.fetcher.data[f.subAddr.WhoURL()] = who

	env := f.signPartyEnvelope(f.subAddr.String(), f.lookup.Address().String())
	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

func TestRegistrationSignatureMayFollowPublicationSignature(t *testing.T) {
	// A subject that signs publication-first (no audience) and appends
	// the registration signature binds just as well: the audience is
	// searched, not read from the first signature.
	f := newFixture(t)
	party := &org.Party{
		Name:      "Alice",
		Endpoints: []*org.Endpoint{{URI: f.subAddr.URI()}},
	}
	env, err := gobl.Envelop(party)
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject, head.WithIssuer(f.subAddr.String())))
	require.NoError(t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.lookup.Address().String())))

	body, _ := json.Marshal(env)
	resp := f.post(goblnet.InboxPath, body)
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}
