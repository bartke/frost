package messages

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bartke/threshold-signatures-ed25519/eddsa"
	"github.com/bartke/threshold-signatures-ed25519/party"
	"github.com/bartke/threshold-signatures-ed25519/ristretto"
	"github.com/bartke/threshold-signatures-ed25519/scalar"
)

// A signer represents the state we store for one particular
// co-signer. It can safely be reset once a signature has
// been generated, or an abort was detected.
type signer struct {
	// signer's additive share of the Public key.
	// It is multiplied by the party's Lagrange coefficient
	// so the we do need to do so later.
	Public ristretto.Element

	// Di = [di]•B
	// Ei = [ei]•B
	Di, Ei ristretto.Element

	// Ri = Di + [ρ] Ei
	// This is a share of the nonce R
	Ri ristretto.Element

	// Pi = ρ = H(i, Message, B)
	// This is the 'rho' from the paper
	Pi ristretto.Scalar

	// Zi = z = d + (e • ρ) + 𝛌 • s • c
	// This is the share of the final signature
	Zi ristretto.Scalar
}

func NewSigner() signer {
	var s signer
	s.Reset()
	return s
}

// Reset sets all values to default.
// The party is no longer usable since the public key is deleted.
func (signer *signer) Reset() {
	signer.Ei.Set(ristretto.Identity)
	signer.Di.Set(ristretto.Identity)

	signer.Ri.Set(ristretto.Identity)

	signer.Pi.Set(ristretto.Zero)
	signer.Zi.Set(ristretto.Zero)
}

func (s *signer) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Di     string `json:"di"`
		Ei     string `json:"ei"`
		Pi     string `json:"pi"`
		Ri     string `json:"ri"`
		Zi     string `json:"zi"`
		Public string `json:"public"`
	}{
		Di:     base64.StdEncoding.EncodeToString(s.Di.Bytes()),
		Ei:     base64.StdEncoding.EncodeToString(s.Ei.Bytes()),
		Pi:     base64.StdEncoding.EncodeToString(s.Pi.Bytes()),
		Ri:     base64.StdEncoding.EncodeToString(s.Ri.Bytes()),
		Zi:     base64.StdEncoding.EncodeToString(s.Zi.Bytes()),
		Public: base64.StdEncoding.EncodeToString(s.Public.Bytes()),
	})
}

func (s *signer) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Di     string `json:"di"`
		Ei     string `json:"ei"`
		Pi     string `json:"pi"`
		Ri     string `json:"ri"`
		Zi     string `json:"zi"`
		Public string `json:"public"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	diBytes, err := base64.StdEncoding.DecodeString(aux.Di)
	if err != nil {
		return err
	}

	if _, err := s.Di.SetCanonicalBytes(diBytes); err != nil {
		return err
	}

	eiBytes, err := base64.StdEncoding.DecodeString(aux.Ei)
	if err != nil {
		return err
	}

	_, err = s.Ei.SetCanonicalBytes(eiBytes)
	if err != nil {
		return err
	}

	piBytes, err := base64.StdEncoding.DecodeString(aux.Pi)
	if err != nil {
		return err
	}

	_, err = s.Pi.SetCanonicalBytes(piBytes)
	if err != nil {
		return err
	}

	riBytes, err := base64.StdEncoding.DecodeString(aux.Ri)
	if err != nil {
		return err
	}

	_, err = s.Ri.SetCanonicalBytes(riBytes)
	if err != nil {
		return err
	}

	ziBytes, err := base64.StdEncoding.DecodeString(aux.Zi)
	if err != nil {
		return err
	}

	_, err = s.Zi.SetCanonicalBytes(ziBytes)
	if err != nil {
		return err
	}

	publicBytes, err := base64.StdEncoding.DecodeString(aux.Public)
	if err != nil {
		return err
	}

	_, err = s.Public.SetCanonicalBytes(publicBytes)
	if err != nil {
		return err
	}

	return nil
}

type SignerState struct {
	SelfID    party.ID
	SignerIDs party.IDSlice
	Message   []byte
	Parties   map[party.ID]*signer
	// GroupKey is the GroupKey, i.e. the public key associated to the group of signers.
	GroupKey       eddsa.PublicKey
	SecretKeyShare ristretto.Scalar
	// e and d are the scalars committed to in the first round
	E, D ristretto.Scalar
	// C = H(R, GroupKey, Message)
	C ristretto.Scalar
	// R = ∑ Ri
	R ristretto.Element
}

func (s *SignerState) MarshalJSON() ([]byte, error) {
	idBytes := s.SelfID.Bytes()
	msg := base64.StdEncoding.EncodeToString(s.Message)
	groupKeyBytes, err := s.GroupKey.MarshalJSON()
	if err != nil {
		return nil, err
	}
	secretBytes := s.SecretKeyShare.Bytes()
	eBytes := s.E.Bytes()
	dBytes := s.D.Bytes()
	cBytes := s.C.Bytes()
	rBytes := s.R.Bytes()
	parties := make(map[string]string, len(s.Parties))
	for id, party := range s.Parties {
		partyBytes, err := party.MarshalJSON()
		if err != nil {
			return nil, err
		}
		parties[base64.StdEncoding.EncodeToString(id.Bytes())] = base64.StdEncoding.EncodeToString(partyBytes)
	}
	return json.Marshal(&struct {
		SelfID         string            `json:"self_id"`
		SignerIDs      party.IDSlice     `json:"signer_ids"`
		Message        string            `json:"message"`
		GroupKey       string            `json:"group_key"`
		SecretKeyShare string            `json:"secret_key_share"`
		E              string            `json:"e"`
		D              string            `json:"d"`
		C              string            `json:"c"`
		R              string            `json:"r"`
		Signers        map[string]string `json:"signers"`
	}{
		SelfID:         base64.StdEncoding.EncodeToString(idBytes),
		SignerIDs:      s.SignerIDs,
		Message:        msg,
		GroupKey:       base64.StdEncoding.EncodeToString(groupKeyBytes),
		SecretKeyShare: base64.StdEncoding.EncodeToString(secretBytes),
		E:              base64.StdEncoding.EncodeToString(eBytes),
		D:              base64.StdEncoding.EncodeToString(dBytes),
		C:              base64.StdEncoding.EncodeToString(cBytes),
		R:              base64.StdEncoding.EncodeToString(rBytes),
		Signers:        parties,
	})
}

func (s *SignerState) UnmarshalJSON(data []byte) error {
	aux := &struct {
		SelfID         string            `json:"self_id"`
		SignerIDs      party.IDSlice     `json:"signer_ids"`
		Message        string            `json:"message"`
		GroupKey       string            `json:"group_key"`
		SecretKeyShare string            `json:"secret_key_share"`
		E              string            `json:"e"`
		D              string            `json:"d"`
		C              string            `json:"c"`
		R              string            `json:"r"`
		Signers        map[string]string `json:"signers"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	idBytes, err := base64.StdEncoding.DecodeString(aux.SelfID)
	if err != nil {
		return err
	}

	s.SelfID, err = party.FromBytes(idBytes)
	if err != nil {
		return err
	}

	s.SignerIDs = aux.SignerIDs

	msg, err := base64.StdEncoding.DecodeString(aux.Message)
	if err != nil {
		return err
	}
	s.Message = msg

	groupKeyBytes, err := base64.StdEncoding.DecodeString(aux.GroupKey)
	if err != nil {
		return err
	}
	err = s.GroupKey.UnmarshalJSON(groupKeyBytes)
	if err != nil {
		return err
	}

	secretBytes, err := base64.StdEncoding.DecodeString(aux.SecretKeyShare)
	if err != nil {
		return err
	}
	_, err = s.SecretKeyShare.SetBytesWithClamping(secretBytes)
	if err != nil {
		return err
	}

	eBytes, err := base64.StdEncoding.DecodeString(aux.E)
	if err != nil {
		return err
	}
	_, err = s.E.SetBytesWithClamping(eBytes)
	if err != nil {
		return err
	}

	dBytes, err := base64.StdEncoding.DecodeString(aux.D)
	if err != nil {
		return err
	}
	_, err = s.D.SetBytesWithClamping(dBytes)
	if err != nil {
		return err
	}

	cBytes, err := base64.StdEncoding.DecodeString(aux.C)
	if err != nil {
		return err
	}
	_, err = s.C.SetBytesWithClamping(cBytes)
	if err != nil {
		return err
	}

	rBytes, err := base64.StdEncoding.DecodeString(aux.R)
	if err != nil {
		return err
	}
	_, err = s.R.SetCanonicalBytes(rBytes)
	if err != nil {
		return err
	}

	s.Parties = make(map[party.ID]*signer, len(aux.Signers))
	for idStr, partyStr := range aux.Signers {
		idBytes, err := base64.StdEncoding.DecodeString(idStr)
		if err != nil {
			return err
		}

		partyID, err := party.FromBytes(idBytes)
		if err != nil {
			return err
		}
		partyBytes, err := base64.StdEncoding.DecodeString(partyStr)
		if err != nil {
			return err
		}
		sig := &signer{}
		err = sig.UnmarshalJSON(partyBytes)
		if err != nil {
			return err
		}
		s.Parties[partyID] = sig
	}

	return nil
}

func SignRound0(partyIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte) (*Message, *SignerState, error) {
	if !partyIDs.Contains(secret.ID) {
		return nil, nil, errors.New("base.NewRound: owner of SecretShare is not contained in partyIDs")
	}

	if !partyIDs.IsSubsetOf(shares.PartyIDs) {
		return nil, nil, fmt.Errorf("base.NewRound: partyIDs %v are not a subset of shares.PartyIDs %v", partyIDs, shares.PartyIDs)
	}

	state := &SignerState{
		SelfID:         secret.ID,
		SignerIDs:      partyIDs,
		Message:        message,
		Parties:        make(map[party.ID]*signer, partyIDs.N()),
		GroupKey:       *shares.GroupKey,
		SecretKeyShare: secret.Secret,
	}

	state.R.Set(ristretto.Identity)

	// Setup parties
	for _, id := range partyIDs {
		s := NewSigner()
		// var s signer
		if id == 0 {
			return nil, nil, errors.New("base.NewRound: id 0 is not valid")
		}

		originalShare, ok := shares.Shares[id]
		if !ok {
			return nil, nil, fmt.Errorf("base.NewRound: party %d not found in shares", id)
		}

		lagrange, err := id.Lagrange(partyIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("base.NewRound: %w", err)
		}
		s.Public.ScalarMult(lagrange, originalShare)
		state.Parties[id] = &s
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := state.SelfID.Lagrange(partyIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("base.NewRound: %w", err)
	}
	state.SecretKeyShare.Multiply(lagrange, &secret.Secret)

	// Generate first message
	selfParty := state.Parties[state.SelfID]

	// Sample dᵢ, Dᵢ = [dᵢ] B
	scalar.SetScalarRandom(&state.D)
	selfParty.Di.ScalarBaseMult(&state.D)
	// Sample eᵢ, Dᵢ = [eᵢ] B
	scalar.SetScalarRandom(&state.E)
	selfParty.Ei.ScalarBaseMult(&state.E)

	msg := NewSign1(state.SelfID, &selfParty.Di, &selfParty.Ei)
	return msg, state, nil
}

func SignRound1(state *SignerState, inputMsgs []*Message) (*Message, *SignerState, error) {
	// Process Sign1 messages
	for _, msg := range inputMsgs {
		id := msg.From
		otherParty := state.Parties[id]
		if msg.Sign1.Di.Equal(ristretto.Identity) == 1 || msg.Sign1.Ei.Equal(ristretto.Identity) == 1 {
			return nil, nil, errors.New("commitment Ei or Di was the identity")
		}
		otherParty.Di.Set(&msg.Sign1.Di)
		otherParty.Ei.Set(&msg.Sign1.Ei)
	}

	state.computeRhos()

	state.R.Set(ristretto.Identity)
	for _, p := range state.Parties {
		// Ri = D + [ρ] E
		p.Ri.ScalarMult(&p.Pi, &p.Ei)
		p.Ri.Add(&p.Ri, &p.Di)

		// R += Ri
		state.R.Add(&state.R, &p.Ri)
	}

	// c = H(R, GroupKey, M)
	state.C.Set(eddsa.ComputeChallenge(&state.R, &state.GroupKey, state.Message))

	selfParty := state.Parties[state.SelfID]

	// Compute z = d + (e • ρ) + 𝛌 • s • c
	// Note: since we multiply the secret by the Lagrange coefficient,
	// can ignore 𝛌=1
	secretShare := &selfParty.Zi
	secretShare.Multiply(&state.SecretKeyShare, &state.C)         // s • c
	secretShare.MultiplyAdd(&state.E, &selfParty.Pi, secretShare) // (e • ρ) + s • c
	secretShare.Add(secretShare, &state.D)                        // d + (e • ρ) + 𝛌 • s • c

	msg := NewSign2(state.SelfID, secretShare)
	return msg, state, nil
}

func SignRound2(state *SignerState, inputMsgs []*Message) (*eddsa.Signature, *SignerState, error) {
	// Process Sign2 messages
	for _, msg := range inputMsgs {
		id := msg.From
		otherParty := state.Parties[id]

		var publicNeg, RPrime ristretto.Element
		publicNeg.Negate(&otherParty.Public)

		// RPrime = [c](-A) + [s]B
		RPrime.VarTimeDoubleScalarBaseMult(&state.C, &publicNeg, &msg.Sign2.Zi)
		if RPrime.Equal(&otherParty.Ri) != 1 {
			return nil, nil, errors.New("signature share is invalid")
		}
		otherParty.Zi.Set(&msg.Sign2.Zi)
	}

	// S = ∑ sᵢ
	S := ristretto.NewScalar()
	for _, otherParty := range state.Parties {
		// s += sᵢ
		S.Add(S, &otherParty.Zi)
	}

	sig := &eddsa.Signature{
		R: state.R,
		S: *S,
	}

	if !state.GroupKey.Verify(state.Message, sig) {
		return nil, nil, errors.New("full signature is invalid")
	}

	return sig, state, nil
}

// computeRhos computes the binding factors (ρ values) for each participant in
// the signing process. It uses a hash function to create these binding factors
// based on a combination of the message to be signed, the identities of the
// participants, and their respective commitments. This ensures that each
// participant's contribution to the final signature is uniquely bound to their
// identity and the message, enhancing the security and integrity of the
// threshold signing process.
func (state *SignerState) computeRhos() {
	var hashDomainSeparation = []byte("FROST-SHA512")
	messageHash := sha512.Sum512(state.Message)

	sizeB := int(state.SignerIDs.N() * (party.IDByteSize + 32 + 32))
	bufferHeader := len(hashDomainSeparation) + party.IDByteSize + len(messageHash)
	sizeBuffer := bufferHeader + sizeB
	offsetID := len(hashDomainSeparation)

	// We compute the binding factor 𝜌_{i} for each party as such:
	//
	//     𝜌_d = SHA-512 ("FROST-SHA512" ∥ i ∥ SHA-512(Message) ∥ B )
	//
	// For each party ID i.
	//
	// The list B is the concatenation of ( j ∥ Dⱼ ∥ Eⱼ ) for all signers j in sorted order.
	//     B = (ID1 ∥ D₁ ∥ E₁) ∥ (ID_2 ∥ D₂ ∥ E₂) ∥ ... ∥ (ID_N ∥ D_N ∥ E_N)

	// We compute the big buffer "FROST-SHA512" ∥ ... ∥ SHA-512(Message) ∥ B
	// and remember the offset of ... . Later we will write the ID of each party at this place.
	buffer := make([]byte, 0, sizeBuffer)
	buffer = append(buffer, hashDomainSeparation...)
	buffer = append(buffer, state.SelfID.Bytes()...)
	buffer = append(buffer, messageHash[:]...)

	// compute B
	for _, id := range state.SignerIDs {
		otherParty := state.Parties[id]
		buffer = append(buffer, id.Bytes()...)
		buffer = append(buffer, otherParty.Di.Bytes()...)
		buffer = append(buffer, otherParty.Ei.Bytes()...)
	}

	for _, id := range state.SignerIDs {
		// Update the four bytes with the ID
		copy(buffer[offsetID:], id.Bytes())

		// Pi = ρ = H ("FROST-SHA512" ∥ Message ∥ B ∥ ID )
		digest := sha512.Sum512(buffer)
		_, _ = state.Parties[id].Pi.SetUniformBytes(digest[:])
	}
}
