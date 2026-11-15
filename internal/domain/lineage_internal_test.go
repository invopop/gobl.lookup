package domain

import (
	"testing"
	"time"

	"github.com/invopop/gobl/dsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

func TestNextLineage(t *testing.T) {
	now := time.Now()
	a, b, c := dsig.NewES256Key(), dsig.NewES256Key(), dsig.NewES256Key()
	pub := func(ks ...*dsig.PrivateKey) []*dsig.PublicKey {
		out := make([]*dsig.PublicKey, len(ks))
		for i, k := range ks {
			out[i] = k.Public()
		}
		return out
	}
	lineage := func(ks ...*dsig.PrivateKey) []*models.LineageKey {
		out := make([]*models.LineageKey, len(ks))
		for i, k := range ks {
			out[i] = &models.LineageKey{JKT: k.JKT(), KID: k.ID()}
		}
		return out
	}
	jkts := func(l []*models.LineageKey) []string {
		out := make([]string, len(l))
		for i, k := range l {
			out[i] = k.JKT
		}
		return out
	}

	t.Run("rolls over with the current key signing second", func(t *testing.T) {
		got, err := nextLineage(lineage(a), pub(b, a), nil, now)
		require.NoError(t, err)
		assert.Equal(t, []string{a.JKT(), b.JKT()}, jkts(got))
	})

	t.Run("rejects a key bound before becoming current again", func(t *testing.T) {
		_, err := nextLineage(lineage(a, b), pub(b, a), nil, now)
		assert.ErrorIs(t, err, errLineage)
		_, err = nextLineage(lineage(a, b), pub(a, b), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})

	t.Run("rejects two keys neither of which is current", func(t *testing.T) {
		_, err := nextLineage(lineage(a), pub(b, c), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})

	t.Run("orders a first registration by the verified key", func(t *testing.T) {
		got, err := nextLineage(nil, pub(a, b), []string{b.JKT()}, now)
		require.NoError(t, err)
		assert.Equal(t, []string{b.JKT(), a.JKT()}, jkts(got))
	})

	t.Run("rejects a first registration with both or neither key verified", func(t *testing.T) {
		_, err := nextLineage(nil, pub(a, b), []string{a.JKT(), b.JKT()}, now)
		assert.ErrorIs(t, err, errLineage)
		_, err = nextLineage(nil, pub(a, b), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})

	t.Run("rejects more than two keys", func(t *testing.T) {
		_, err := nextLineage(lineage(a), pub(a, b, c), nil, now)
		assert.ErrorIs(t, err, errLineage)
	})
}

func TestInLineage(t *testing.T) {
	k := dsig.NewES256Key()
	l := []*models.LineageKey{{JKT: k.JKT()}}
	assert.True(t, inLineage(l, k.JKT()))
	assert.False(t, inLineage(l, ""))
	assert.False(t, inLineage(l, "other"))
}
