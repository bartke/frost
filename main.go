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
	// N is the number of participants
	N := party.Size(5)
	// T is the threshold
	var T party.ID = 2

	fmt.Printf("Starting MPC Key Generation with N=%d and T=%d\n", N, T)

	partyIDs := helpers.GenerateSet(N)
	states, outputs := keyGeneration(partyIDs, T)

	secrets := collectSecrets(partyIDs, states, outputs)

	// the group public key and public shares are the same for all parties
	groupPublicKey := outputs[partyIDs[0]].Public.GroupKey
	publicShares := outputs[partyIDs[0]].Public

	if err := validateSecrets(secrets, groupPublicKey, publicShares); err != nil {
		fmt.Println("Validation Error:", err)
	}

	fmt.Println("Starting MPC Signing...")
	signature := mpcSigning(partyIDs, outputs, publicShares, message)

	// verification using Ed25519
	pk := publicShares.GroupKey
	if !ed25519.Verify(pk.ToEd25519(), []byte(message), signature.ToEd25519()) {
		fmt.Println("Signature verification failed using ed25519")
	}

	if !pk.Verify([]byte(message), signature) {
		fmt.Println("Signature verification failed using custom function")
	}

	fmt.Println("MPC Key Generation and Signing completed successfully.")
}

func keyGeneration(partyIDs []party.ID, T party.ID) (map[party.ID]*state.State, map[party.ID]*keygen.Output) {
	states := map[party.ID]*state.State{}
	outputs := map[party.ID]*keygen.Output{}

	// initialize key generation states
	for _, id := range partyIDs {
		var err error
		states[id], outputs[id], err = frost.NewKeygenState(id, partyIDs, T, 0)
		if err != nil {
			fmt.Println("Keygen Error:", err)
			return nil, nil
		}
	}

	msgsOut1 := make([][]byte, 0, len(partyIDs))
	msgsOut2 := make([][]byte, 0, len(partyIDs)*(len(partyIDs)-1)/2)

	// round 1: commit phase
	for _, s := range states {
		// initial phase with no input messages
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println("Keygen Error:", err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}

	// round 2: share phase
	for _, s := range states {
		// Ppocess commitments
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println("Keygen Error:", err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}

	// finalizing key generation
	for _, s := range states {
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println("Keygen Error:", err)
		}
	}

	return states, outputs
}

func collectSecrets(partyIDs []party.ID, states map[party.ID]*state.State, outputs map[party.ID]*keygen.Output) map[party.ID]*eddsa.SecretShare {
	secrets := map[party.ID]*eddsa.SecretShare{}
	groupPublicKey := outputs[partyIDs[0]].Public.GroupKey
	publicShares := outputs[partyIDs[0]].Public

	for _, id := range partyIDs {
		if err := states[id].WaitForError(); err != nil {
			fmt.Println("Keygen Error:", err)
		}
		groupKey := outputs[id].Public.GroupKey
		shares := outputs[id].Public
		secrets[id] = outputs[id].SecretKey
		if err := compareOutput(groupPublicKey, groupKey, publicShares, shares); err != nil {
			fmt.Println("Comparison Error:", err)
		}
	}

	return secrets
}

func mpcSigning(partyIDs []party.ID, outputs map[party.ID]*keygen.Output, publicShares *eddsa.Public, message string) *eddsa.Signature {
	N := len(partyIDs)
	T := N - 1

	signSet := helpers.GenerateSet(party.Size(T))
	secretShares := map[party.ID]*eddsa.SecretShare{}
	for _, id := range signSet {
		secretShares[id] = outputs[id].SecretKey
	}

	states := map[party.ID]*state.State{}
	signOutputs := map[party.ID]*sign.Output{}
	msgsOut1 := make([][]byte, 0, N)
	msgsOut2 := make([][]byte, 0, N)

	// initialize signing states
	for _, id := range signSet {
		var err error
		states[id], signOutputs[id], err = frost.NewSignState(signSet, secretShares[id], publicShares, []byte(message), 0)
		if err != nil {
			fmt.Println("Sign Error:", err)
		}
	}

	// round 1: nonce generation and sharing
	start := time.Now()
	for _, s := range states {
		// nonce generation
		msgs1, err := helpers.PartyRoutine(nil, s)
		if err != nil {
			fmt.Println("Sign Error:", err)
		}
		msgsOut1 = append(msgsOut1, msgs1...)
	}
	fmt.Println("Finish round 0", time.Since(start))

	// round 2: partial signature generation
	start = time.Now()
	for _, s := range states {
		// process nonces
		msgs2, err := helpers.PartyRoutine(msgsOut1, s)
		if err != nil {
			fmt.Println("Sign Error:", err)
		}
		msgsOut2 = append(msgsOut2, msgs2...)
	}
	fmt.Println("Finish round 1", time.Since(start))

	// finalizing the signature
	start = time.Now()
	for _, s := range states {
		// generate partial signatures
		_, err := helpers.PartyRoutine(msgsOut2, s)
		if err != nil {
			fmt.Println("Sign Error:", err)
		}
	}
	fmt.Println("Finish round 2", time.Since(start))

	sig := signOutputs[signSet[0]].Signature
	if sig == nil {
		fmt.Println("Signature is nil")
		return nil
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

	return sig
}

// compareOutput compares the output of key generation from two parties.
func compareOutput(groupKey1, groupKey2 *eddsa.PublicKey, publicShares1, publicShares2 *eddsa.Public) error {
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

// validateSecrets validates the combined secret shares using Lagrange Interpolation.
func validateSecrets(secrets map[party.ID]*eddsa.SecretShare, groupKey *eddsa.PublicKey, shares *eddsa.Public) error {
	fullSecret := ristretto.NewScalar()

	for id, secret := range secrets {
		pk1 := &secret.Public
		pk2, ok := shares.Shares[id]
		if !ok {
			return errors.New("party has no share")
		}

		if pk1.Equal(pk2) != 1 {
			return errors.New("public keys are not the same")
		}

		lagrange, err := id.Lagrange(shares.PartyIDs)
		if err != nil {
			return err
		}
		fullSecret.MultiplyAdd(lagrange, &secret.Secret, fullSecret)
	}

	fullPk := eddsa.NewPublicKeyFromPoint(new(ristretto.Element).ScalarBaseMult(fullSecret))
	if !groupKey.Equal(fullPk) {
		return errors.New("computed group key does not match")
	}

	return nil
}
