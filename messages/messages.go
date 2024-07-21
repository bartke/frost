package messages

import (
	"encoding/base64"
	"encoding/json"

	"errors"

	"github.com/bartke/threshold-signatures-ed25519/party"
	"github.com/bartke/threshold-signatures-ed25519/polynomial"
	"github.com/bartke/threshold-signatures-ed25519/ristretto"
	"github.com/bartke/threshold-signatures-ed25519/zk"
)

type Header struct {
	// Type is the message type
	Type MessageType

	// From returns the party.ID of the party who sent this message.
	// Cannot be 0
	From party.ID

	// To is the party.ID of the party the message is addressed to.
	// If the message is intended for broadcast, the ID returned is 0 (invalid),
	// therefore, you should call IsBroadcast() first.
	To party.ID
}

func (h *Header) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Type string `json:"type"`
		From string `json:"from"`
		To   string `json:"to"`
	}{
		Type: base64.StdEncoding.EncodeToString([]byte{byte(h.Type)}),
		From: base64.StdEncoding.EncodeToString(h.From.Bytes()),
		To:   base64.StdEncoding.EncodeToString(h.To.Bytes()),
	})
}

func (h *Header) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Type string `json:"type"`
		From string `json:"from"`
		To   string `json:"to"`
	}{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	typeBytes, err := base64.StdEncoding.DecodeString(aux.Type)
	if err != nil {
		return err
	}
	h.Type = MessageType(typeBytes[0])

	fromBytes, err := base64.StdEncoding.DecodeString(aux.From)
	if err != nil {
		return err
	}
	h.From, err = party.FromBytes(fromBytes)
	if err != nil {
		return err
	}

	toBytes, err := base64.StdEncoding.DecodeString(aux.To)
	if err != nil {
		return err
	}
	h.To, err = party.FromBytes(toBytes)
	return err
}

type Message struct {
	Header
	KeyGen1 *KeyGen1
	KeyGen2 *KeyGen2
	// Sign1   *Sign1
	// Sign2   *Sign2
}

var ErrInvalidMessage = errors.New("invalid message")

type MessageType uint8

// MessageType s must be increasing.
const (
	MessageTypeNone MessageType = iota
	MessageTypeKeyGen1
	MessageTypeKeyGen2
	MessageTypeSign1
	MessageTypeSign2
)

func (m *Message) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Header  Header   `json:"header"`
		KeyGen1 *KeyGen1 `json:"keygen1,omitempty"`
		KeyGen2 *KeyGen2 `json:"keygen2,omitempty"`
	}{
		Header:  m.Header,
		KeyGen1: m.KeyGen1,
		KeyGen2: m.KeyGen2,
	})
}

func (m *Message) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Header  Header   `json:"header"`
		KeyGen1 *KeyGen1 `json:"keygen1,omitempty"`
		KeyGen2 *KeyGen2 `json:"keygen2,omitempty"`
	}{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	m.Header = aux.Header
	m.KeyGen1 = aux.KeyGen1
	m.KeyGen2 = aux.KeyGen2

	return nil
}

type KeyGen1 struct {
	Proof       *zk.Schnorr
	Commitments *polynomial.Exponent
}

func NewKeyGen1(from party.ID, proof *zk.Schnorr, commitments *polynomial.Exponent) *Message {
	return &Message{
		Header: Header{
			Type: MessageTypeKeyGen1,
			From: from,
		},
		KeyGen1: &KeyGen1{
			Proof:       proof,
			Commitments: commitments,
		},
	}
}

func (m *KeyGen1) MarshalJSON() ([]byte, error) {
	proofBytes, err := m.Proof.MarshalBinary()
	if err != nil {
		return nil, err
	}
	commitmentsBytes, err := m.Commitments.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		Proof       string `json:"proof"`
		Commitments string `json:"commitments"`
	}{
		Proof:       base64.StdEncoding.EncodeToString(proofBytes),
		Commitments: base64.StdEncoding.EncodeToString(commitmentsBytes),
	})
}

func (m *KeyGen1) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Proof       string `json:"proof"`
		Commitments string `json:"commitments"`
	}{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	proofBytes, err := base64.StdEncoding.DecodeString(aux.Proof)
	if err != nil {
		return err
	}

	m.Proof = &zk.Schnorr{}
	if err := m.Proof.UnmarshalBinary(proofBytes); err != nil {
		return err
	}

	commitmentsBytes, err := base64.StdEncoding.DecodeString(aux.Commitments)
	if err != nil {
		return err
	}

	m.Commitments = &polynomial.Exponent{}
	return m.Commitments.UnmarshalBinary(commitmentsBytes)
}

type KeyGen2 struct {
	// Share is a Shamir additive share for the destination party
	Share ristretto.Scalar
}

func NewKeyGen2(from, to party.ID, share *ristretto.Scalar) *Message {
	return &Message{
		Header: Header{
			Type: MessageTypeKeyGen2,
			From: from,
			To:   to,
		},
		KeyGen2: &KeyGen2{Share: *share},
	}
}

func (m *KeyGen2) MarshalJSON() ([]byte, error) {
	shareBytes := m.Share.Bytes()
	return json.Marshal(&struct {
		Share string `json:"share"`
	}{
		Share: base64.StdEncoding.EncodeToString(shareBytes),
	})
}

func (m *KeyGen2) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Share string `json:"share"`
	}{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	shareBytes, err := base64.StdEncoding.DecodeString(aux.Share)
	if err != nil {
		return err
	}
	_, err = m.Share.SetCanonicalBytes(shareBytes)
	return err
}
