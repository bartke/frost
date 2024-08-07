package messages

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bartke/threshold-signatures-ed25519/eddsa"
	"github.com/bartke/threshold-signatures-ed25519/party"
	"github.com/bartke/threshold-signatures-ed25519/polynomial"
	"github.com/bartke/threshold-signatures-ed25519/ristretto"
	"github.com/bartke/threshold-signatures-ed25519/scalar"
	"github.com/bartke/threshold-signatures-ed25519/zk"
)

type State struct {
	SelfID         party.ID
	PartyIDs       party.IDSlice
	Threshold      party.Size
	Polynomial     *polynomial.Polynomial
	Secret         ristretto.Scalar
	Commitments    map[party.ID]*polynomial.Exponent
	CommitmentsSum *polynomial.Exponent
}

func (s *State) MarshalJSON() ([]byte, error) {
	idBytes := s.SelfID.Bytes()
	polyntBytes, err := s.Polynomial.MarshalBinary()
	if err != nil {
		return nil, err
	}

	var csumbytes []byte
	if s.CommitmentsSum != nil {
		csumbytes, err = s.CommitmentsSum.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}

	secretBytes := s.Secret.Bytes()
	return json.Marshal(&struct {
		ID             string            `json:"id"`
		PartyIDs       party.IDSlice     `json:"party_ids"`
		Threshold      party.Size        `json:"threshold"`
		Polynomial     string            `json:"polynomial"`
		Secret         string            `json:"secret"`
		Commitments    map[string]string `json:"commitments"`
		CommitmentsSum string            `json:"commitments_sum"`
	}{
		ID:         base64.StdEncoding.EncodeToString(idBytes),
		PartyIDs:   s.PartyIDs,
		Threshold:  s.Threshold,
		Polynomial: base64.StdEncoding.EncodeToString(polyntBytes),
		Secret:     base64.StdEncoding.EncodeToString(secretBytes),
		Commitments: func() map[string]string {
			aux := make(map[string]string, len(s.Commitments))
			for id, exp := range s.Commitments {
				expBytes, err := exp.MarshalBinary()
				if err != nil {
					return nil
				}
				aux[base64.StdEncoding.EncodeToString(id.Bytes())] = base64.StdEncoding.EncodeToString(expBytes)
			}
			return aux
		}(),
		CommitmentsSum: base64.StdEncoding.EncodeToString(csumbytes),
	})
}

func (s *State) UnmarshalJSON(data []byte) error {
	aux := &struct {
		ID             string            `json:"id"`
		PartyIDs       party.IDSlice     `json:"party_ids"`
		Threshold      party.Size        `json:"threshold"`
		Polynomial     string            `json:"polynomial"`
		Secret         string            `json:"secret"`
		Commitments    map[string]string `json:"commitments"`
		CommitmentsSum string            `json:"commitments_sum"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	idBytes, err := base64.StdEncoding.DecodeString(aux.ID)
	if err != nil {
		return err
	}

	s.PartyIDs = aux.PartyIDs
	s.Threshold = aux.Threshold

	polyntBytes, err := base64.StdEncoding.DecodeString(aux.Polynomial)
	if err != nil {
		return err
	}

	secretBytes, err := base64.StdEncoding.DecodeString(aux.Secret)
	if err != nil {
		return err
	}

	s.SelfID, err = party.FromBytes(idBytes)
	if err != nil {
		return err
	}

	s.Polynomial = &polynomial.Polynomial{}
	if err := s.Polynomial.UnmarshalBinary(polyntBytes); err != nil {
		return err
	}

	_, err = s.Secret.SetCanonicalBytes(secretBytes)
	if err != nil {
		return err
	}

	s.Commitments = make(map[party.ID]*polynomial.Exponent, len(aux.Commitments))
	for id, exp := range aux.Commitments {
		idBytes, err := base64.StdEncoding.DecodeString(id)
		if err != nil {
			return err
		}
		partyID, err := party.FromBytes(idBytes)
		if err != nil {
			return err
		}

		expBytes, err := base64.StdEncoding.DecodeString(exp)
		if err != nil {
			return err
		}

		s.Commitments[partyID] = &polynomial.Exponent{}
		if err := s.Commitments[partyID].UnmarshalBinary(expBytes); err != nil {
			return err
		}
	}

	s.CommitmentsSum = polynomial.NewPolynomialExponent(s.Polynomial)
	expBytes, err := base64.StdEncoding.DecodeString(aux.CommitmentsSum)
	if err != nil {
		return err
	}

	if err := s.CommitmentsSum.UnmarshalBinary(expBytes); err != nil {
		return err
	}

	return nil
}

// Round 0: Initializing participants
func Round0(selfID party.ID, n, t party.Size) (*Message, *State, error) {
	partyIDs := make([]party.ID, 0, n)
	for i := party.ID(1); i <= n; i++ {
		partyIDs = append(partyIDs, i)
	}

	state := &State{
		SelfID:    selfID,
		PartyIDs:  partyIDs,
		Threshold: t,
	}

	scalar.SetScalarRandom(&state.Secret)

	state.Polynomial = polynomial.NewPolynomial(t, &state.Secret)
	state.CommitmentsSum = polynomial.NewPolynomialExponent(state.Polynomial)

	ctx := make([]byte, 32) // context to prevent replay attacks
	public := state.CommitmentsSum.Constant()
	proof := zk.NewSchnorrProof(selfID, public, ctx, &state.Secret)

	// We use the variable Secret to hold the sum of all shares received.
	// Therefore, we can set it to the share we would send to our selves.
	state.Secret.Set(state.Polynomial.Evaluate(selfID.Scalar()))

	return NewKeyGen1(selfID, proof, state.CommitmentsSum), state, nil
}

// Round 1: Processing KeyGen1 messages and generating KeyGen2 messages
func Round1(state *State, inputMsgs []*Message) ([]*Message, *State, error) {
	// process KeyGen1 messages
	for _, msg := range inputMsgs {
		id := msg.From
		if id == state.SelfID {
			continue
		}

		if msg.Type != MessageTypeKeyGen1 {
			return nil, nil, errors.New("invalid message type for round 1")
		}

		public := msg.KeyGen1.Commitments.Constant()
		ctx := make([]byte, 32)

		if !msg.KeyGen1.Proof.Verify(id, public, ctx) {
			return nil, nil, errors.New("ZK Schnorr verification failed")
		}

		state.Commitments[id] = msg.KeyGen1.Commitments
		state.CommitmentsSum.Add(msg.KeyGen1.Commitments)
	}

	// generate KeyGen2 messages
	msgsOut := make([]*Message, 0, len(state.PartyIDs)-1)
	for _, id := range state.PartyIDs {
		if id == state.SelfID {
			continue
		}

		share := state.Polynomial.Evaluate(id.Scalar())
		keygen2 := NewKeyGen2(state.SelfID, id, share)
		msgsOut = append(msgsOut, keygen2)
	}

	state.Secret.Set(state.Polynomial.Evaluate(state.SelfID.Scalar()))

	return msgsOut, state, nil
}

// Round 2: Processing KeyGen2 messages and finalizing the key generation
func Round2(state *State, inputMsgs []*Message) (*eddsa.Public, *eddsa.SecretShare, error) {
	// process KeyGen2 messages
	for _, msg := range inputMsgs {
		if msg.Type != MessageTypeKeyGen2 {
			return nil, nil, errors.New("invalid message type for round 2")
		}

		if msg.From == state.SelfID {
			continue
		}

		id := msg.From
		var computedShareExp ristretto.Element
		computedShareExp.ScalarBaseMult(&msg.KeyGen2.Share)

		if _, ok := state.Commitments[id]; !ok {
			return nil, nil, fmt.Errorf("missing commitment for party %d", id)
		}

		shareExp := state.Commitments[id].Evaluate(state.SelfID.Scalar())
		if computedShareExp.Equal(shareExp) != 1 {
			// Verifiable Secret Sharing (VSS) validation failed
			return nil, nil, errors.New("VSS validation failed")
		}

		state.Secret.Add(&state.Secret, &msg.KeyGen2.Share)
		// msg.KeyGen2.Share.Set(ristretto.NewScalar())
	}

	shares := make(map[party.ID]*ristretto.Element, len(state.Commitments))
	for _, id := range state.PartyIDs {
		shares[id] = state.CommitmentsSum.Evaluate(id.Scalar())
	}

	pub := &eddsa.Public{
		PartyIDs:  state.PartyIDs,
		Threshold: state.Threshold,
		Shares:    shares,
		GroupKey:  eddsa.NewPublicKeyFromPoint(state.CommitmentsSum.Constant()),
	}

	sec := eddsa.NewSecretShare(state.SelfID, &state.Secret)
	return pub, sec, nil
}
