package frost

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bartke/frost/eddsa"
	"github.com/bartke/frost/party"
	"github.com/bartke/frost/ristretto"
	"github.com/bartke/frost/scalar"
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

func NewSigner() *signer {
	return &signer{
		Public: *ristretto.NewIdentityElement(),
		Di:     *ristretto.NewIdentityElement(),
		Ei:     *ristretto.NewIdentityElement(),
		Ri:     *ristretto.NewIdentityElement(),
		Pi:     *ristretto.NewScalar(),
		Zi:     *ristretto.NewScalar(),
	}
}

func (s *signer) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Di     ristretto.Element `json:"di"`
		Ei     ristretto.Element `json:"ei"`
		Pi     string            `json:"pi"`
		Ri     ristretto.Element `json:"ri"`
		Zi     string            `json:"zi"`
		Public ristretto.Element `json:"public"`
	}{
		Di:     s.Di,
		Ei:     s.Ei,
		Pi:     base64.StdEncoding.EncodeToString(s.Pi.Bytes()),
		Ri:     s.Ri,
		Zi:     base64.StdEncoding.EncodeToString(s.Zi.Bytes()),
		Public: s.Public,
	})
}

func (s *signer) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Di     ristretto.Element `json:"di"`
		Ei     ristretto.Element `json:"ei"`
		Pi     string            `json:"pi"`
		Ri     ristretto.Element `json:"ri"`
		Zi     string            `json:"zi"`
		Public ristretto.Element `json:"public"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	if err := decodeScalar(aux.Pi, &s.Pi); err != nil {
		return err
	}

	if err := decodeScalar(aux.Zi, &s.Zi); err != nil {
		return err
	}

	s.Di = aux.Di
	s.Ei = aux.Ei
	s.Ri = aux.Ri
	s.Public = aux.Public

	return nil
}

type SignerState struct {
	SelfID    party.ID
	SignerIDs party.IDSlice
	Message   []byte
	Signers   map[party.ID]*signer
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
	parties := make(map[string]*signer, len(s.Signers))
	for id, party := range s.Signers {
		parties[base64.StdEncoding.EncodeToString(id.Bytes())] = party
	}
	return json.Marshal(&struct {
		SelfID         string             `json:"self_id"`
		SignerIDs      party.IDSlice      `json:"signer_ids"`
		Message        string             `json:"message"`
		GroupKey       eddsa.PublicKey    `json:"group_key"`
		SecretKeyShare string             `json:"secret_key_share"`
		E              string             `json:"e"`
		D              string             `json:"d"`
		C              string             `json:"c"`
		R              ristretto.Element  `json:"r"`
		Signers        map[string]*signer `json:"signers"`
	}{
		SelfID:         base64.StdEncoding.EncodeToString(s.SelfID.Bytes()),
		SignerIDs:      s.SignerIDs,
		Message:        base64.StdEncoding.EncodeToString(s.Message),
		GroupKey:       s.GroupKey,
		SecretKeyShare: base64.StdEncoding.EncodeToString(s.SecretKeyShare.Bytes()),
		E:              base64.StdEncoding.EncodeToString(s.E.Bytes()),
		D:              base64.StdEncoding.EncodeToString(s.D.Bytes()),
		C:              base64.StdEncoding.EncodeToString(s.C.Bytes()),
		R:              s.R,
		Signers:        parties,
	})
}

func (s *SignerState) UnmarshalJSON(data []byte) error {
	aux := &struct {
		SelfID         string             `json:"self_id"`
		SignerIDs      party.IDSlice      `json:"signer_ids"`
		Message        string             `json:"message"`
		GroupKey       eddsa.PublicKey    `json:"group_key"`
		SecretKeyShare string             `json:"secret_key_share"`
		E              string             `json:"e"`
		D              string             `json:"d"`
		C              string             `json:"c"`
		R              ristretto.Element  `json:"r"`
		Signers        map[string]*signer `json:"signers"`
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
	s.GroupKey = aux.GroupKey

	if err := decodeScalar(aux.SecretKeyShare, &s.SecretKeyShare); err != nil {
		return err
	}

	if err := decodeScalar(aux.E, &s.E); err != nil {
		return err
	}

	if err := decodeScalar(aux.D, &s.D); err != nil {
		return err
	}

	if err := decodeScalar(aux.C, &s.C); err != nil {
		return err
	}

	s.R = aux.R

	s.Signers = make(map[party.ID]*signer, len(aux.Signers))
	for idStr, signer := range aux.Signers {
		idBytes, err := base64.StdEncoding.DecodeString(idStr)
		if err != nil {
			return err
		}

		partyID, err := party.FromBytes(idBytes)
		if err != nil {
			return err
		}

		s.Signers[partyID] = signer
	}

	return nil
}

// SignInit initializes the state for the signing protocol.
func SignInit(signerIDs party.IDSlice, secret *eddsa.SecretShare, shares *eddsa.Public, message []byte) (*Message, *SignerState, error) {
	if !signerIDs.Contains(secret.ID) {
		return nil, nil, errors.New("SignRound0: owner of SecretShare is not contained in partyIDs")
	}

	if !signerIDs.IsSubsetOf(shares.PartyIDs) {
		return nil, nil, fmt.Errorf("SignRound0: partyIDs %v are not a subset of shares.PartyIDs %v", signerIDs, shares.PartyIDs)
	}

	state := &SignerState{
		SelfID:    secret.ID,
		SignerIDs: signerIDs,
		Message:   message,
		Signers:   make(map[party.ID]*signer, signerIDs.N()),
		GroupKey:  *shares.GroupKey,
		R:         *ristretto.NewIdentityElement(),
	}

	// Setup parties
	for _, id := range signerIDs {
		s := NewSigner()
		if id == 0 {
			return nil, nil, errors.New("SignRound0: id 0 is not valid")
		}

		originalShare, ok := shares.Shares[id]
		if !ok {
			return nil, nil, fmt.Errorf("SignRound0: party %d not found in shares", id)
		}

		lagrange, err := id.Lagrange(signerIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("SignRound0: %w", err)
		}
		s.Public.ScalarMult(lagrange, originalShare)
		state.Signers[id] = s
	}

	// Normalize secret share so that we can assume we are dealing with an additive sharing
	lagrange, err := state.SelfID.Lagrange(signerIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("SignRound0: %w", err)
	}
	state.SecretKeyShare.Multiply(lagrange, &secret.Secret)

	// Generate first message
	selfParty := state.Signers[state.SelfID]

	// Sample dᵢ, Dᵢ = [dᵢ] B
	scalar.SetScalarRandom(&state.D)
	selfParty.Di.ScalarBaseMult(&state.D)
	// Sample eᵢ, Dᵢ = [eᵢ] B
	scalar.SetScalarRandom(&state.E)
	selfParty.Ei.ScalarBaseMult(&state.E)

	msg := NewSign1(state.SelfID, &selfParty.Di, &selfParty.Ei)
	return msg, state, nil
}

// SignRound1 processes the first round of the signing protocol.
func SignRound1(state *SignerState, inputMsgs []*Message) (*Message, *SignerState, error) {
	// Process Sign1 messages
	for _, msg := range inputMsgs {
		if msg.From == state.SelfID {
			continue
		}

		id := msg.From
		otherParty := state.Signers[id]
		if msg.Sign1.Di.Equal(ristretto.NewIdentityElement()) == 1 || msg.Sign1.Ei.Equal(ristretto.NewIdentityElement()) == 1 {
			return nil, nil, errors.New("commitment Ei or Di was the identity")
		}
		otherParty.Di.Set(&msg.Sign1.Di)
		otherParty.Ei.Set(&msg.Sign1.Ei)
	}

	// Generate Sign2 messages
	state.computeRhos()

	state.R.Set(ristretto.NewIdentityElement())
	for _, id := range state.SignerIDs {
		p := state.Signers[id]

		// mutate Ri in place
		// Ri = Di + [ρi] Ei
		p.Ri.ScalarMult(&p.Pi, &p.Ei)
		p.Ri.Add(&p.Ri, &p.Di)

		// R += Ri
		state.R.Add(&state.R, &p.Ri)
	}

	// R must be the same for all parties, the sum of all Ri
	// fmt.Printf("R: %v\n", state.R)

	// c = H(R, GroupKey, M)
	state.C.Set(eddsa.ComputeChallenge(&state.R, &state.GroupKey, state.Message))

	// the challenge c must be the same for all parties

	selfParty := state.Signers[state.SelfID]

	// Compute partial signature:
	// z = d + (e • ρ) + 𝛌 • s • c
	// Note: since we multiply the secret by the Lagrange coefficient,
	// can ignore 𝛌=1
	secretShare := &selfParty.Zi
	secretShare.Multiply(&state.SecretKeyShare, &state.C)         // s • c
	secretShare.MultiplyAdd(&state.E, &selfParty.Pi, secretShare) // (e • ρ) + s • c
	secretShare.Add(secretShare, &state.D)                        // d + (e • ρ) + 𝛌 • s • c

	msg := NewSign2(state.SelfID, secretShare)
	return msg, state, nil
}

// SignRound2 computes the final signature.
func SignRound2(state *SignerState, inputMsgs []*Message) (*eddsa.Signature, *SignerState, error) {
	// Process Sign2 messages
	for _, msg := range inputMsgs {
		if msg.From == state.SelfID {
			continue
		}

		id := msg.From
		otherParty, ok := state.Signers[id]
		if !ok {
			return nil, nil, fmt.Errorf("SignRound2: party %d not found in shares", id)
		}

		var publicNeg, RPrime, ZiB ristretto.Element
		publicNeg.Negate(&otherParty.Public)

		// RPrime = [c](-A) + [zi]B
		ZiB.ScalarBaseMult(&msg.Sign2.Zi)
		RPrime.ScalarMult(&state.C, &publicNeg)
		RPrime.Add(&ZiB, &RPrime)

		// Verify the signature share
		if RPrime.Equal(&otherParty.Ri) != 1 {
			fmt.Printf("222  Calculated RPrime: %v\n", RPrime)
			return nil, nil, errors.New("signature share is invalid")
		}

		otherParty.Zi.Set(&msg.Sign2.Zi)
	}

	// Generate output

	// S = ∑ sᵢ
	S := ristretto.NewScalar()
	for _, otherParty := range state.Signers {
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
		otherParty := state.Signers[id]
		buffer = append(buffer, id.Bytes()...)
		buffer = append(buffer, otherParty.Di.Bytes()...)
		buffer = append(buffer, otherParty.Ei.Bytes()...)
	}

	for _, id := range state.SignerIDs {
		// Update the four bytes with the ID
		copy(buffer[offsetID:], id.Bytes())

		// Pi = ρ = H ("FROST-SHA512" ∥ Message ∥ B ∥ ID )
		digest := sha512.Sum512(buffer)
		_, _ = state.Signers[id].Pi.SetUniformBytes(digest[:])
	}
}
