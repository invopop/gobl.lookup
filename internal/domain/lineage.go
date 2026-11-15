package domain

import (
	"errors"
	"time"

	"github.com/invopop/gobl/dsig"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.lookup/internal/domain/models"
)

// errLineage is returned when a registration request's keys cannot
// extend or start a lineage.
var errLineage = errors.New("registration must be signed with the current key, a new key, " +
	"or the current key naming a new one with cnf")

// nextLineage applies the signatures confirming a registration request
// to the current lineage (spec §7.3) and returns the resulting one,
// whose last key is bound. In a key change the current key's signature
// must name the new key as its successor. verified holds the cnf
// thumbprints of accepted verification countersignatures on the
// request, which pick the current key of a first registration signed
// with two.
func nextLineage(lineage []*models.LineageKey, confs []*goblnet.ConfirmingSignature, verified []string, now time.Time) ([]*models.LineageKey, error) {
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
		if k.JKT() == current {
			return lineage, nil // renewal
		}
		// A first registration, or a key that is not the current one:
		// a lost key or a new holder of the address starts afresh.
		return []*models.LineageKey{entry(k)}, nil
	case 2:
		// from is the key changed from, to the one it names.
		for _, pair := range [][2]*goblnet.ConfirmingSignature{{confs[0], confs[1]}, {confs[1], confs[0]}} {
			from, to := pair[0], pair[1]
			if from.Successor != to.Key.JKT() {
				continue
			}
			if current != "" {
				// The new key must be new: a key bound before cannot
				// become current again.
				if from.Key.JKT() == current && !inLineage(lineage, to.Key.JKT()) {
					return append(lineage, entry(to.Key)), nil
				}
				continue
			}
			if contains(verified, from.Key.JKT()) && !contains(verified, to.Key.JKT()) {
				return []*models.LineageKey{entry(from.Key), entry(to.Key)}, nil
			}
		}
		return nil, errLineage
	}
	return nil, errLineage
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
