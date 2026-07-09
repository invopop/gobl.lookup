package repos_test

import (
	"context"
	"testing"

	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.lookup/internal/domain/models"
	"github.com/invopop/gobl.lookup/internal/domain/repos"
)

func TestMemoryStorePutGet(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryRegistrations()
	addr := net.Address("alice.example")
	r := models.NewRegistration(addr, uuid.V7())

	err := s.Put(ctx, r)
	require.NoError(t, err)
	assert.NotEmpty(t, r.Rev)

	got, err := s.Get(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, addr, got.Address)
	assert.Equal(t, models.StatusReceived, got.Status)
	assert.NotEmpty(t, got.Rev)
}

func TestMemoryStoreGetMissing(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryRegistrations()
	_, err := s.Get(ctx, "nobody.example")
	require.ErrorIs(t, err, repos.ErrNotFound)
}

func TestMemoryStoreGetByUUID(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryRegistrations()
	envUUID := uuid.V7()
	r := models.NewRegistration("alice.example", envUUID)
	err := s.Put(ctx, r)
	require.NoError(t, err)

	got, err := s.GetByUUID(ctx, envUUID)
	require.NoError(t, err)
	assert.Equal(t, net.Address("alice.example"), got.Address)

	_, err = s.GetByUUID(ctx, uuid.V7())
	require.ErrorIs(t, err, repos.ErrNotFound)
}

func TestMemoryStoreUpdateRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryRegistrations()
	r := models.NewRegistration("alice.example", uuid.V7())
	err := s.Put(ctx, r)
	require.NoError(t, err)

	// Re-read to pick up the new _rev, advance status, write back.
	got, err := s.Get(ctx, "alice.example")
	require.NoError(t, err)
	got.Status = models.StatusDelivered
	err = s.Put(ctx, got)
	require.NoError(t, err)

	final, err := s.Get(ctx, "alice.example")
	require.NoError(t, err)
	assert.Equal(t, models.StatusDelivered, final.Status)
}

func TestMemoryStorePutWithoutMatchingRevConflicts(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryRegistrations()
	r := models.NewRegistration("alice.example", uuid.V7())
	err := s.Put(ctx, r)
	require.NoError(t, err)

	// Drop the rev and try to write again — should conflict.
	r.Rev = ""
	err = s.Put(ctx, r)
	require.ErrorIs(t, err, repos.ErrConflict)
}

func TestMemoryStorePutNewRecordRejectsStaleRev(t *testing.T) {
	ctx := context.Background()
	s := repos.NewMemoryRegistrations()
	r := models.NewRegistration("alice.example", uuid.V7())
	// Pretend the caller has a rev for a doc that doesn't exist.
	r.Rev = "1-deadbeef"
	err := s.Put(ctx, r)
	require.ErrorIs(t, err, repos.ErrConflict)
}

func TestRegistrationValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(r *models.Registration)
		wantErr string
	}{
		{"no address", func(r *models.Registration) { r.Address = "" }, "address is required"},
		{"no status", func(r *models.Registration) { r.Status = "" }, "status is required"},
		{"mismatched id", func(r *models.Registration) { r.ID = "registration:wrong" }, "does not match address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := models.NewRegistration("alice.example", uuid.V7())
			tc.mutate(r)
			err := r.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestNilRegistrationValidateErrors(t *testing.T) {
	var r *models.Registration
	err := r.Validate()
	require.Error(t, err)
}
