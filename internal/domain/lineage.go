package domain

import (
	"errors"
	"time"

	"github.com/invopop/gobl/dsig"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// errLineage is returned when a registration request's keys cannot
// renew, change or start a lineage.
var errLineage = errors.New("registration must be signed with the current key, " +
	"the current key naming a new one with cnf and that new key, or one new key")

// nextLineage applies the signatures confirming a registration request
// to the current lineage (spec §7.3) and returns the resulting one,
// whose last key is bound: the current key alone renews, the current
// key naming a new one with cnf, signed with both, changes key, and one
// key not in the lineage starts a new one.
func nextLineage(lineage []*models.LineageKey, confs []*goblnet.ConfirmingSignature, now time.Time) ([]*models.LineageKey, error) {
	entry := func(k *dsig.PublicKey) *models.LineageKey {
		return &models.LineageKey{JKT: k.JKT(), KID: k.ID(), AddedAt: now}
	}
	var current string
	if len(lineage) > 0 {
		current = lineage[len(lineage)-1].JKT
	}
	switch len(confs) {
	case 1:
		k := confs[0].Key
		switch {
		case k.JKT() == current:
			return lineage, nil // renewal
		case inLineage(lineage, k.JKT()):
			return nil, errLineage // a key bound before cannot become current again
		}
		// A first registration, a lost key, or a new holder of the
		// address: a new lineage starts.
		return []*models.LineageKey{entry(k)}, nil
	case 2:
		if current == "" {
			return nil, errLineage
		}
		for _, pair := range [][2]*goblnet.ConfirmingSignature{{confs[0], confs[1]}, {confs[1], confs[0]}} {
			from, to := pair[0], pair[1]
			if from.Key.JKT() == current && from.Successor == to.Key.JKT() && !inLineage(lineage, to.Key.JKT()) {
				return append(lineage, entry(to.Key)), nil
			}
		}
	}
	return nil, errLineage
}
