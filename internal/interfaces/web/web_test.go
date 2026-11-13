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

func (m *mockFetcher) Post(_ context.Context, _ string, _ []byte) error {
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
	accepted  int
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
	client := goblnet.NewClient(goblnet.WithFetcher(fetcher), goblnet.WithIdentity(lookup.Address(), lookup.PrivateKey))
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
	// fixture serves the subject's identity, signed for the lookup.
	who, _ := json.Marshal(f.request(f.party(), f.subject))
	fetcher.data[subAddr.WhoURL()] = who
	return f
}

// party returns a fresh party document for the subject.
func (f *fixture) party() *org.Party {
	return &org.Party{Name: "Alice"}
}

// request envelopes party as a registration request from the subject
// to the lookup, signed with each of keys.
func (f *fixture) request(party *org.Party, keys ...*dsig.PrivateKey) *gobl.Envelope {
	f.t.Helper()
	env, err := gobl.Envelop(party)
	require.NoError(f.t, err)
	f.signRequest(env, keys...)
	return env
}

// signRequest signs env from the subject to the lookup with each of
// keys, publishing each key at the subject's address.
func (f *fixture) signRequest(env *gobl.Envelope, keys ...*dsig.PrivateKey) {
	f.t.Helper()
	for _, k := range keys {
		f.publish(k)
		require.NoError(f.t, goblnet.Sign(env, k, f.subAddr, f.lookup.Address()))
	}
}

// publish serves key at the subject's key endpoint.
func (f *fixture) publish(key *dsig.PrivateKey) {
	pub, _ := json.Marshal(key.Public())
	f.fetcher.data[f.subAddr.KeyURL(key.ID())] = pub
}

// register POSTs env to the lookup's inbox and returns the status.
func (f *fixture) register(env *gobl.Envelope) int {
	f.t.Helper()
	body, err := json.Marshal(env)
	require.NoError(f.t, err)
	resp := f.do(http.MethodPost, goblnet.InboxPath, body, "")
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusAccepted {
		f.accepted++
	}
	return resp.StatusCode
}

// record returns the stored registration for the subject.
func (f *fixture) record() *models.Registration {
	f.t.Helper()
	rec, err := f.registry.Get(context.Background(), f.subAddr)
	require.NoError(f.t, err)
	return rec
}

// counterSignAsVerifier stamps the fixture verifier's countersignature
// for the subject onto env, binding key, as a provider would after
// completing its checks.
func (f *fixture) counterSignAsVerifier(env *gobl.Envelope, key *dsig.PrivateKey) {
	f.t.Helper()
	opts := []head.SignOption{
		head.WithIssuer(f.verifAddr.String()),
		head.WithAudience(f.subAddr.String()),
		head.WithExpiration(time.Now().Add(365 * 24 * time.Hour)),
	}
	if key != nil {
		opts = append(opts, head.WithConfirmation(key.JKT()))
	}
	require.NoError(f.t, env.Sign(f.verifier, opts...))
}

// authority returns the payload of the lookup's countersignature on env.
func (f *fixture) authority(env *gobl.Envelope) *head.SigningPayload {
	f.t.Helper()
	for _, sig := range env.Signatures {
		p, err := head.SignedPayload(sig)
		require.NoError(f.t, err)
		if p.Iss == f.lookup.Address().String() {
			return p
		}
	}
	f.t.Fatal("no lookup countersignature")
	return nil
}

// renewal returns the envelope the lookup delivered to the subject,
// signed again as a request to the lookup with keys.
func (f *fixture) renewal(keys ...*dsig.PrivateKey) *gobl.Envelope {
	f.t.Helper()
	sent := f.waitForDeliveries(f.accepted)
	require.Len(f.t, sent, f.accepted)
	data, err := json.Marshal(sent[len(sent)-1].env)
	require.NoError(f.t, err)
	env := new(gobl.Envelope)
	require.NoError(f.t, json.Unmarshal(data, env))
	f.signRequest(env, keys...)
	return env
}

// waitForDeliveries spins until the mock sender records n deliveries
// or two seconds pass. The inbox handler delivers async so the POST
// returns immediately.
func (f *fixture) waitForDeliveries(n int) []sentEnvelope {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := f.sender.records(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return f.sender.records()
}

// bearer mints a request token from the subject for the lookup, as
// any conforming client would attach to a who request.
func (f *fixture) bearer() string {
	f.t.Helper()
	token, err := goblnet.NewToken(f.subject, f.subAddr, f.lookup.Address(), 0)
	require.NoError(f.t, err)
	return "Bearer " + token
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
	env := f.request(f.party(), f.subject)
	require.Equal(t, http.StatusAccepted, f.register(env), "no request token is needed")

	// Delivery happens asynchronously and the mock sender is instant,
	// so the record may already have advanced to delivered.
	rec := f.record()
	assert.Contains(t, []models.Status{models.StatusCountersigned, models.StatusDelivered}, rec.Status)
	assert.Empty(t, rec.Verifier, "initial registration carries no verifier")
	require.Len(t, rec.Lineage, 1)
	assert.Equal(t, f.subject.JKT(), rec.Lineage[0].JKT)
	assert.Equal(t, f.subject.ID(), rec.Lineage[0].KID)

	// The request signature is dropped; the lookup's countersignature
	// addresses the envelope back to the subject.
	out := rec.CountersignedEnvelope
	require.Len(t, out.Signatures, 1)
	assert.Equal(t, f.lookup.Address().URI(), out.Head.From)
	assert.Equal(t, f.subAddr.URI(), out.Head.To)
	p := f.authority(out)
	assert.Equal(t, f.subAddr.String(), p.Aud)
	require.NotNil(t, p.Confirmation)
	assert.Equal(t, f.subject.JKT(), p.Confirmation.JKT)
	assert.Empty(t, p.Verifier)
	assert.Greater(t, p.ExpiresAt, time.Now().Add(89*24*time.Hour).Unix())
	assert.LessOrEqual(t, p.ExpiresAt, time.Now().Add(90*24*time.Hour).Unix())

	// Discovery link stamped on the (mutable) header.
	require.NotEmpty(t, out.Head.Links)
	link := out.Head.Links[0]
	assert.Equal(t, head.LinkCategoryKeyVerification, link.Category)
	assert.Equal(t, cbc.Key("lookup"), link.Key)
	assert.Contains(t, link.URL, env.Head.UUID.String())

	sent := f.waitForDeliveries(1)
	require.Len(t, sent, 1)
	assert.Equal(t, f.subAddr, sent[0].to)
	assert.Equal(t, env.Head.UUID, sent[0].env.Head.UUID)

	// The delivered envelope is a valid GOBL Net delivery to the
	// subject, endorsed by the lookup for the subject's key.
	lookupPub, _ := json.Marshal(f.lookup.PrivateKey.Public())
	f.fetcher.data[f.lookup.Address().KeyURL(f.lookup.PrivateKey.ID())] = lookupPub
	c := goblnet.NewClient(goblnet.WithFetcher(f.fetcher))
	require.NoError(t, c.VerifyDelivery(context.Background(), sent[0].env, f.subAddr))
}

func TestInboxRejectsRequests(t *testing.T) {
	f := newFixture(t)
	other := dsig.NewES256Key()

	t.Run("not a party", func(t *testing.T) {
		env, err := gobl.Envelop(&org.Inbox{Code: "x"})
		require.NoError(t, err)
		f.signRequest(env, f.subject)
		assert.Equal(t, http.StatusUnprocessableEntity, f.register(env))
	})

	t.Run("signed by an unpublished key", func(t *testing.T) {
		env, err := gobl.Envelop(f.party())
		require.NoError(t, err)
		require.NoError(t, goblnet.Sign(env, other, f.subAddr, f.lookup.Address()))
		assert.Equal(t, http.StatusUnauthorized, f.register(env))
	})

	t.Run("signed for another audience", func(t *testing.T) {
		env, err := gobl.Envelop(f.party())
		require.NoError(t, err)
		require.NoError(t, goblnet.Sign(env, f.subject, f.subAddr, "someone.example"))
		env.Head.To = f.lookup.Address().URI()
		assert.Equal(t, http.StatusUnauthorized, f.register(env))
	})

	t.Run("addressed to another participant", func(t *testing.T) {
		env, err := gobl.Envelop(f.party())
		require.NoError(t, err)
		require.NoError(t, goblnet.Sign(env, f.subject, f.subAddr, "someone.example"))
		assert.Equal(t, http.StatusUnauthorized, f.register(env))
	})

	t.Run("from naming another address", func(t *testing.T) {
		env := f.request(f.party(), f.subject)
		env.Head.From = "gobl:victim.example"
		assert.Equal(t, http.StatusUnauthorized, f.register(env))
	})

	t.Run("oversized body", func(t *testing.T) {
		resp := f.do(http.MethodPost, goblnet.InboxPath, bytes.Repeat([]byte("a"), (1<<20)+1024), "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})

	t.Run("malformed JSON", func(t *testing.T) {
		resp := f.do(http.MethodPost, goblnet.InboxPath, []byte("not json"), "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("forged countersignature claiming the lookup", func(t *testing.T) {
		env := f.request(f.party(), f.subject)
		require.NoError(t, env.Sign(other,
			head.WithIssuer(f.lookup.Address().String()),
			head.WithAudience(f.subAddr.String())))
		assert.Equal(t, http.StatusUnauthorized, f.register(env))
	})

	_, err := f.registry.Get(context.Background(), f.subAddr)
	assert.ErrorIs(t, err, repos.ErrNotFound, "nothing was registered")
}

func TestKeyLineage(t *testing.T) {
	t.Run("renewal with the current key keeps the lineage", func(t *testing.T) {
		f := newFixture(t)
		require.Equal(t, http.StatusAccepted, f.register(f.request(f.party(), f.subject)))
		first := f.record().Lineage

		require.Equal(t, http.StatusAccepted, f.register(f.renewal(f.subject)))
		rec := f.record()
		assert.Equal(t, first, rec.Lineage)
		require.Len(t, rec.CountersignedEnvelope.Signatures, 1, "request signature dropped, own countersignature superseded")
		assert.Equal(t, 1, linkCount(rec.CountersignedEnvelope), "restamped, not duplicated")
		require.NoError(t, rec.CountersignedEnvelope.Validate())
	})

	t.Run("rollover signed with both keys keeps the verifier", func(t *testing.T) {
		f := newFixture(t)
		env := f.request(f.party(), f.subject)
		f.counterSignAsVerifier(env, f.subject)
		require.Equal(t, http.StatusAccepted, f.register(env))
		require.Equal(t, f.verifAddr, f.record().Verifier)

		next := dsig.NewES256Key()
		require.Equal(t, http.StatusAccepted, f.register(f.renewal(f.subject, next)))
		rec := f.record()
		require.Len(t, rec.Lineage, 2)
		assert.Equal(t, f.subject.JKT(), rec.Lineage[0].JKT)
		assert.Equal(t, next.JKT(), rec.Lineage[1].JKT)
		assert.Equal(t, f.verifAddr, rec.Verifier, "the verification binds a key in the lineage")
		p := f.authority(rec.CountersignedEnvelope)
		assert.Equal(t, next.JKT(), p.Confirmation.JKT)
		assert.Equal(t, f.verifAddr.String(), p.Verifier)

		// And on to a third key, signed with the second.
		third := dsig.NewES256Key()
		require.Equal(t, http.StatusAccepted, f.register(f.renewal(next, third)))
		rec = f.record()
		require.Len(t, rec.Lineage, 3)
		assert.Equal(t, f.verifAddr, rec.Verifier)
	})

	t.Run("a new key alone starts a new lineage and drops the verifier", func(t *testing.T) {
		// A lost key, or a new holder of the address: the previous
		// verification does not carry over.
		f := newFixture(t)
		env := f.request(f.party(), f.subject)
		f.counterSignAsVerifier(env, f.subject)
		require.Equal(t, http.StatusAccepted, f.register(env))

		newHolder := dsig.NewES256Key()
		require.Equal(t, http.StatusAccepted, f.register(f.renewal(newHolder)))
		rec := f.record()
		require.Len(t, rec.Lineage, 1)
		assert.Equal(t, newHolder.JKT(), rec.Lineage[0].JKT)
		assert.Empty(t, rec.Verifier)
		assert.Nil(t, rec.VerifiedAt)
		assert.Empty(t, f.authority(rec.CountersignedEnvelope).Verifier)
	})

	t.Run("two keys at a first registration follow the verification", func(t *testing.T) {
		f := newFixture(t)
		next := dsig.NewES256Key()
		env := f.request(f.party(), f.subject, next)
		f.counterSignAsVerifier(env, f.subject)
		require.Equal(t, http.StatusAccepted, f.register(env))
		rec := f.record()
		require.Len(t, rec.Lineage, 2)
		assert.Equal(t, f.subject.JKT(), rec.Lineage[0].JKT)
		assert.Equal(t, next.JKT(), rec.Lineage[1].JKT)
		assert.Equal(t, f.verifAddr, rec.Verifier)
	})

	t.Run("two keys at a first registration without a verification are rejected", func(t *testing.T) {
		f := newFixture(t)
		env := f.request(f.party(), f.subject, dsig.NewES256Key())
		assert.Equal(t, http.StatusUnprocessableEntity, f.register(env))
	})

	t.Run("two keys, neither current, are rejected", func(t *testing.T) {
		f := newFixture(t)
		require.Equal(t, http.StatusAccepted, f.register(f.request(f.party(), f.subject)))
		assert.Equal(t, http.StatusUnprocessableEntity,
			f.register(f.renewal(dsig.NewES256Key(), dsig.NewES256Key())))
	})
}

func TestAutoVerify(t *testing.T) {
	t.Run("names an accepted verifier binding the subject's key", func(t *testing.T) {
		f := newFixture(t)
		env := f.request(f.party(), f.subject)
		f.counterSignAsVerifier(env, f.subject)
		require.Equal(t, http.StatusAccepted, f.register(env))
		rec := f.record()
		assert.Equal(t, f.verifAddr, rec.Verifier)
		assert.NotNil(t, rec.VerifiedAt)
		assert.Equal(t, f.verifAddr.String(), f.authority(rec.CountersignedEnvelope).Verifier)
	})

	t.Run("survives renewal of the delivered envelope", func(t *testing.T) {
		f := newFixture(t)
		env := f.request(f.party(), f.subject)
		f.counterSignAsVerifier(env, f.subject)
		require.Equal(t, http.StatusAccepted, f.register(env))
		verifiedAt := f.record().VerifiedAt

		require.Equal(t, http.StatusAccepted, f.register(f.renewal(f.subject)))
		rec := f.record()
		assert.Equal(t, f.verifAddr, rec.Verifier)
		assert.Equal(t, verifiedAt, rec.VerifiedAt, "renewal keeps the verification timestamp")
		final := rec.CountersignedEnvelope
		require.Len(t, final.Signatures, 2, "lookup + verifier, nothing stale")
		assert.Equal(t, 1, sigCountBy(final, f.lookup.Address()))
		assert.Equal(t, 1, sigCountBy(final, f.verifAddr))
	})

	ignored := map[string]func(f *fixture, env *gobl.Envelope){
		"for another key": func(f *fixture, env *gobl.Envelope) {
			f.counterSignAsVerifier(env, dsig.NewES256Key())
		},
		"without a cnf": func(f *fixture, env *gobl.Envelope) {
			f.counterSignAsVerifier(env, nil)
		},
		"for another address": func(f *fixture, env *gobl.Envelope) {
			require.NoError(f.t, env.Sign(f.verifier,
				head.WithIssuer(f.verifAddr.String()),
				head.WithAudience("copier.example"),
				head.WithConfirmation(f.subject.JKT())))
		},
		"forged": func(f *fixture, env *gobl.Envelope) {
			require.NoError(f.t, env.Sign(dsig.NewES256Key(),
				head.WithIssuer(f.verifAddr.String()),
				head.WithAudience(f.subAddr.String()),
				head.WithConfirmation(f.subject.JKT())))
		},
	}
	for name, stamp := range ignored {
		t.Run("ignores a verification "+name, func(t *testing.T) {
			f := newFixture(t)
			env := f.request(f.party(), f.subject)
			stamp(f, env)
			require.Equal(t, http.StatusAccepted, f.register(env), "registration proceeds unverified")
			rec := f.record()
			assert.Empty(t, rec.Verifier)
			assert.Nil(t, rec.VerifiedAt)
		})
	}
}

func TestVerifyDerivesFromStoredEnvelope(t *testing.T) {
	// A provider countersignature received while the provider was not
	// yet on the accepted list is picked up later by the verify
	// command — the recovery path.
	f := newFixture(t)
	bare := domain.New(domain.Deps{
		Identity:      f.lookup,
		Registrations: f.registry,
		Client:        goblnet.NewClient(goblnet.WithFetcher(f.fetcher), goblnet.WithIdentity(f.lookup.Address(), f.lookup.PrivateKey)),
		Sender:        f.sender,
		PublicBaseURL: "https://lookup.example",
		Logger:        discardLogger(),
	})
	env := f.request(f.party(), f.subject)
	f.counterSignAsVerifier(env, f.subject)
	_, err := bare.Registrations().Register(context.Background(), env)
	require.NoError(t, err)
	// Let the async delivery goroutine finish its Put before Verify
	// reads and rewrites the record.
	require.NotEmpty(t, f.waitForDeliveries(1))
	require.Empty(t, f.record().Verifier)

	// Simulate a record poisoned with a duplicate discovery link: the
	// verify command heals it.
	rec := f.record()
	rec.CountersignedEnvelope.Head.Links = append(rec.CountersignedEnvelope.Head.Links,
		rec.CountersignedEnvelope.Head.Links[0])
	require.NoError(t, f.registry.Put(context.Background(), rec))

	setup := domain.New(domain.Deps{
		Identity:      f.lookup,
		Registrations: f.registry,
		Client:        goblnet.NewClient(goblnet.WithFetcher(f.fetcher)),
		Sender:        f.sender,
		Verifiers:     []goblnet.Address{f.verifAddr},
		PublicBaseURL: "https://lookup.example",
		Logger:        discardLogger(),
	})
	rec, err = setup.Registrations().Verify(context.Background(), f.subAddr)
	require.NoError(t, err)
	assert.Equal(t, f.verifAddr, rec.Verifier)
	assert.NotNil(t, rec.VerifiedAt)
	assert.Equal(t, 1, linkCount(rec.CountersignedEnvelope))
	require.NoError(t, rec.CountersignedEnvelope.Validate())
	p := f.authority(rec.CountersignedEnvelope)
	assert.Equal(t, f.subject.JKT(), p.Confirmation.JKT)
	assert.Equal(t, 1, sigCountBy(rec.CountersignedEnvelope, f.lookup.Address()))
}

func TestVerifyWithoutAcceptedCountersignature(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, http.StatusAccepted, f.register(f.request(f.party(), f.subject)))
	require.NotEmpty(t, f.waitForDeliveries(1))

	_, err := f.setup().Registrations().Verify(context.Background(), f.subAddr)
	require.Error(t, err)
	assert.True(t, errors.Is(err, domain.ErrValidation))
}

func TestInboxChecksTheSendersWho(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"missing", goblnet.ErrFetchFailed, http.StatusForbidden},
		{"receive-only", goblnet.ErrNoContent, http.StatusForbidden},
		{"deferred", goblnet.ErrPending, http.StatusForbidden},
		{"unavailable", fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable), http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			delete(f.fetcher.data, f.subAddr.WhoURL())
			f.fetcher.errs[f.subAddr.WhoURL()] = tc.err
			assert.Equal(t, tc.status, f.register(f.request(f.party(), f.subject)))
		})
	}
}

func TestInboxKeyUnavailable(t *testing.T) {
	// The sender's key endpoint is unreachable: the lookup answers 503
	// so the sender retries, not a definitive 401.
	f := newFixture(t)
	env := f.request(f.party(), f.subject)
	f.fetcher.errs[f.subAddr.KeyURL(f.subject.ID())] = fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable)
	assert.Equal(t, http.StatusServiceUnavailable, f.register(env))
}

func TestPartiesLookup(t *testing.T) {
	f := newFixture(t)
	env := f.request(f.party(), f.subject)
	require.Equal(t, http.StatusAccepted, f.register(env))
	_ = f.waitForDeliveries(1)

	t.Run("by UUID", func(t *testing.T) {
		resp := f.get("/parties/" + env.Head.UUID.String())
		defer resp.Body.Close() //nolint:errcheck
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got gobl.Envelope
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, env.Head.UUID, got.Head.UUID)
	})

	t.Run("by address", func(t *testing.T) {
		resp := f.get("/parties/" + string(f.subAddr))
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("not found", func(t *testing.T) {
		resp := f.get("/parties/nobody.example")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
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
	assert.Equal(t, f.lookup.Address().URI(), got.Head.From)
	assert.Equal(t, f.subAddr.URI(), got.Head.To, "addressed to the requester")
	require.Len(t, got.Signatures, 1)
	p, err := head.SignedPayload(got.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, f.lookup.Address().String(), p.Iss)
	assert.Equal(t, f.subAddr.String(), p.Aud, "signed for the requester")
}

func TestRequestAuth(t *testing.T) {
	f := newFixture(t)

	t.Run("who without a token is rejected", func(t *testing.T) {
		resp := f.do(http.MethodGet, goblnet.WhoPath, nil, "")
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
		token, err := goblnet.NewToken(dsig.NewES256Key(), "unknown.example", f.lookup.Address(), 0)
		require.NoError(t, err)
		resp := f.do(http.MethodGet, goblnet.WhoPath, nil, "Bearer "+token)
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("token issuer key unavailable", func(t *testing.T) {
		f := newFixture(t)
		f.fetcher.errs[f.subAddr.KeyURL(f.subject.ID())] = fmt.Errorf("%w: HTTP 503", goblnet.ErrUnavailable)
		resp := f.get(goblnet.WhoPath)
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("keys and parties stay open", func(t *testing.T) {
		resp := f.do(http.MethodGet, goblnet.KeyPath(f.lookup.PrivateKey.ID()), nil, "")
		defer resp.Body.Close() //nolint:errcheck
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestHealth(t *testing.T) {
	f := newFixture(t)
	resp := f.get("/healthz")
	defer resp.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// setup returns a domain setup sharing the fixture's store, sender and
// fetcher, accepting the fixture's verifier.
func (f *fixture) setup() *domain.Setup {
	return domain.New(domain.Deps{
		Identity:      f.lookup,
		Registrations: f.registry,
		Client:        goblnet.NewClient(goblnet.WithFetcher(f.fetcher), goblnet.WithIdentity(f.lookup.Address(), f.lookup.PrivateKey)),
		Sender:        f.sender,
		Verifiers:     []goblnet.Address{f.verifAddr},
		PublicBaseURL: "https://lookup.example",
		Logger:        discardLogger(),
	})
}

// linkCount counts the lookup discovery links on an envelope.
func linkCount(env *gobl.Envelope) int {
	n := 0
	for _, l := range env.Head.Links {
		if l != nil && l.Category == head.LinkCategoryKeyVerification && l.Key == "lookup" {
			n++
		}
	}
	return n
}

// sigCountBy counts signatures by issuer address.
func sigCountBy(env *gobl.Envelope, addr goblnet.Address) int {
	n := 0
	for _, sig := range env.Signatures {
		if p, err := head.SignedPayload(sig); err == nil {
			if iss, ierr := goblnet.ParseAddress(p.Iss); ierr == nil && iss == addr {
				n++
			}
		}
	}
	return n
}
