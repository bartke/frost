package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/sign"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func main() {
	const message = "Hello, MPC!"
	// N is the number of parties
	N := party.Size(5)
	// T is the threshold
	var T party.ID = 2

	fmt.Printf("Starting MPC Key Generation with N=%d and T=%d\n", N, T)

	partyIDs := helpers.GenerateSet(N)
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*keygen.Output{}

	for _, id := range partyIDs {
		var err error
		states[id], outputs[id], err = frost.NewKeygenState(id, partyIDs, T, 0)
		if err != nil {
			fmt.Println("Keygen Error:", err)
			return
		}
	}

	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N*(N-1)/2)

	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println("Keygen Error:", err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println("Keygen Error:", err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println("Keygen Error:", err)
		}
	}

	id1 := partyIDs[0]
	if err := states[id1].WaitForError(); err != nil {
		fmt.Println("Keygen Error:", err)
	}
	groupKey1 := outputs[id1].Public.GroupKey
	publicShares1 := outputs[id1].Public
	secrets := map[party.ID]*eddsa.SecretShare{}
	for _, id2 := range partyIDs {
		if err := states[id2].WaitForError(); err != nil {
			fmt.Println("Keygen Error:", err)
		}
		groupKey2 := outputs[id2].Public.GroupKey
		publicShares2 := outputs[id2].Public
		secrets[id2] = outputs[id2].SecretKey
		if err := CompareOutput(groupKey1, groupKey2, publicShares1, publicShares2); err != nil {
			fmt.Println("Comparison Error:", err)
		}
	}

	if err := ValidateSecrets(secrets, groupKey1, publicShares1); err != nil {
		fmt.Println("Validation Error:", err)
	}

	fmt.Println("Starting MPC Signing...")
	T = N - 1

	signSet := helpers.GenerateSet(T)
	secretShares := map[party.ID]*eddsa.SecretShare{}
	for _, id := range signSet {
		secretShares[id] = outputs[id].SecretKey
	}

	states = map[party.ID]*state.State{}
	signOutputs := map[party.ID]*sign.Output{}
	msgsOut1 = make([][]byte, 0, N)
	msgsOut2 = make([][]byte, 0, N)

	for _, id := range signSet {
		var err error
		states[id], signOutputs[id], err = frost.NewSignState(signSet, secretShares[id], publicShares1, []byte(message), 0)
		if err != nil {
			fmt.Println("Sign Error:", err)
		}
	}

	start := time.Now()
	for _, s := range states {
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println("Sign Error:", err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}
	fmt.Println("Finish round 0", time.Since(start))

	start = time.Now()
	for _, s := range states {
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println("Sign Error:", err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}
	fmt.Println("Finish round 1", time.Since(start))

	start = time.Now()
	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println("Sign Error:", err)
		}
	}
	fmt.Println("Finish round 2", time.Since(start))

	sig := signOutputs[signSet[0]].Signature
	if sig == nil {
		fmt.Println("Signature is nil")
		return
	}

	pk := publicShares1.GroupKey
	if !ed25519.Verify(pk.ToEd25519(), []byte(message), sig.ToEd25519()) {
		fmt.Println("Signature verification failed using ed25519")
	}
	if !pk.Verify([]byte(message), sig) {
		fmt.Println("Signature verification failed using custom function")
	}

	for id, s := range states {
		if err := s.WaitForError(); err != nil {
			fmt.Println("Sign Error:", err)
		}

		comparedSig := signOutputs[id].Signature
		sigBytes, err := sig.MarshalBinary()
		if err != nil {
			fmt.Println("Sign Error:", err)
		}

		comparedSigBytes, _ := comparedSig.MarshalBinary()
		if !bytes.Equal(sigBytes, comparedSigBytes) {
			fmt.Println("Signatures are not the same")
		}
	}

	fmt.Println("MPC Key Generation and Signing completed successfully.")
}

func CompareOutput(groupKey1, groupKey2 *eddsa.PublicKey, publicShares1, publicShares2 *eddsa.Public) error {
	if !publicShares1.Equal(publicShares2) {
		return errors.New("shares not equal")
	}
	partyIDs1 := publicShares1.PartyIDs
	partyIDs2 := publicShares2.PartyIDs
	if len(partyIDs1) != len(partyIDs2) {
		return errors.New("partyIDs are not the same length")
	}

	for i, id1 := range partyIDs1 {
		if id1 != partyIDs2[i] {
			return errors.New("partyIDs are not the same")
		}

		public1 := publicShares1.Shares[partyIDs1[i]]
		public2 := publicShares2.Shares[partyIDs2[i]]
		if public1.Equal(public2) != 1 {
			return errors.New("different public keys")
		}
	}

	groupKeyComp1 := publicShares1.GroupKey
	groupKeyComp2 := publicShares2.GroupKey

	if !groupKey1.Equal(groupKeyComp1) {
		return errors.New("groupKey1 is not computed the same way")
	}
	if !groupKey2.Equal(groupKeyComp2) {
		return errors.New("groupKey2 is not computed the same way")
	}
	return nil
}

func ValidateSecrets(secrets map[party.ID]*eddsa.SecretShare, groupKey *eddsa.PublicKey, shares *eddsa.Public) error {
	fullSecret := ristretto.NewScalar()

	for id, secret := range secrets {
		pk1 := &secret.Public
		pk2, ok := shares.Shares[id]
		if !ok {
			return errors.New("party %d has no share")
		}

		if pk1.Equal(pk2) != 1 {
			return errors.New("pk not the same")
		}

		lagrange, err := id.Lagrange(shares.PartyIDs)
		if err != nil {
			return err
		}
		fullSecret.MultiplyAdd(lagrange, &secret.Secret, fullSecret)
	}

	fullPk := eddsa.NewPublicKeyFromPoint(new(ristretto.Element).ScalarBaseMult(fullSecret))
	if !groupKey.Equal(fullPk) {
		return errors.New("computed groupKey does not match")
	}

	return nil
}
