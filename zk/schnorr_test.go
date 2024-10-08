package zk

import (
	"testing"

	"github.com/bartke/frost/party"
	"github.com/bartke/frost/ristretto"
	"github.com/bartke/frost/scalar"
	"github.com/stretchr/testify/require"
)

func TestSchnorrProof(t *testing.T) {
	var ctx [32]byte
	partyID := party.ID(42)
	private := scalar.NewScalarRandom()
	public := new(ristretto.Element).ScalarBaseMult(private)
	proof := NewSchnorrProof(partyID, public, ctx[:], private)
	publicComputed := ristretto.NewIdentityElement().ScalarBaseMult(private)
	require.True(t, publicComputed.Equal(public) == 1)
	require.True(t, proof.Verify(partyID, public, ctx[:]))
}
