package registry_test

import (
	"context"
	"testing"

	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.lookup/internal/registry"
)

func TestMemoryStorePutGet(t *testing.T) {
	ctx := context.Background()
	s := registry.NewMemoryStore()
	addr := net.Address("alice.example")
	r := registry.NewRecord(addr, uuid.V7())

	rev, err := s.Put(ctx, r)
	require.NoError(t, err)
	assert.NotEmpty(t, rev)
	assert.Equal(t, rev, r.Rev)

	got, err := s.Get(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, addr, got.Address)
	assert.Equal(t, registry.StatusReceived, got.Status)
	assert.NotEmpty(t, got.Rev)
}

func TestMemoryStoreGetMissing(t *testing.T) {
	ctx := context.Background()
	s := registry.NewMemoryStore()
	_, err := s.Get(ctx, "nobody.example")
	require.ErrorIs(t, err, registry.ErrNotFound)
}

func TestMemoryStoreGetByUUID(t *testing.T) {
	ctx := context.Background()
	s := registry.NewMemoryStore()
	envUUID := uuid.V7()
	r := registry.NewRecord("alice.example", envUUID)
	_, err := s.Put(ctx, r)
	require.NoError(t, err)

	got, err := s.GetByUUID(ctx, envUUID)
	require.NoError(t, err)
	assert.Equal(t, net.Address("alice.example"), got.Address)

	_, err = s.GetByUUID(ctx, uuid.V7())
	require.ErrorIs(t, err, registry.ErrNotFound)
}

func TestMemoryStoreUpdateRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := registry.NewMemoryStore()
	r := registry.NewRecord("alice.example", uuid.V7())
	_, err := s.Put(ctx, r)
	require.NoError(t, err)

	// Re-read to pick up the new _rev, advance status, write back.
	got, err := s.Get(ctx, "alice.example")
	require.NoError(t, err)
	got.Status = registry.StatusDelivered
	_, err = s.Put(ctx, got)
	require.NoError(t, err)

	final, err := s.Get(ctx, "alice.example")
	require.NoError(t, err)
	assert.Equal(t, registry.StatusDelivered, final.Status)
}

func TestMemoryStorePutWithoutMatchingRevConflicts(t *testing.T) {
	ctx := context.Background()
	s := registry.NewMemoryStore()
	r := registry.NewRecord("alice.example", uuid.V7())
	_, err := s.Put(ctx, r)
	require.NoError(t, err)

	// Drop the rev and try to write again — should conflict.
	r.Rev = ""
	_, err = s.Put(ctx, r)
	require.ErrorIs(t, err, registry.ErrConflict)
}

func TestMemoryStorePutNewRecordRejectsStaleRev(t *testing.T) {
	ctx := context.Background()
	s := registry.NewMemoryStore()
	r := registry.NewRecord("alice.example", uuid.V7())
	// Pretend the caller has a rev for a doc that doesn't exist.
	r.Rev = "1-deadbeef"
	_, err := s.Put(ctx, r)
	require.ErrorIs(t, err, registry.ErrConflict)
}

func TestRecordValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(r *registry.Record)
		wantErr string
	}{
		{"no address", func(r *registry.Record) { r.Address = "" }, "address is required"},
		{"no status", func(r *registry.Record) { r.Status = "" }, "status is required"},
		{"mismatched id", func(r *registry.Record) { r.ID = "registration:wrong" }, "does not match address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := registry.NewRecord("alice.example", uuid.V7())
			tc.mutate(r)
			err := r.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestNilRecordValidateErrors(t *testing.T) {
	var r *registry.Record
	err := r.Validate()
	require.Error(t, err)
}
