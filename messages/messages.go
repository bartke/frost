package messages

import (
	"encoding/base64"
	"encoding/json"

	"errors"

	"github.com/bartke/threshold-signatures-ed25519/polynomial"
	"github.com/bartke/threshold-signatures-ed25519/zk"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

const headerSize = 1 + 2*party.IDByteSize

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

func (h *Header) size() int {
	return headerSize
}

func (h *Header) equal(other interface{}) bool {
	if otherMsg, ok := other.(Header); ok {
		return *h == otherMsg
	}
	if otherMsg, ok := other.(*Header); ok {
		return *h == *otherMsg
	}
	return false
}

// IsBroadcast returns true if the message is intended to be broadcast
func (h *Header) IsBroadcast() bool {
	return h.To == 0
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

func (m *Message) Size() int {
	var size int
	switch m.Type {
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil {
			size += m.KeyGen2.size()
		}
		fallthrough
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil {
			size += m.KeyGen1.size()
		}
		//case MessageTypeSign1:
		//	if m.Sign1 != nil {
		//		size = m.Sign1.Size()
		//	}
		//case MessageTypeSign2:
		//	if m.Sign2 != nil {
		//		size = m.Sign2.Size()
		//	}
	}
	return m.Header.size() + size
}
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

func (m *Message) Equal(other interface{}) bool {
	otherMsg, ok := other.(*Message)
	if !ok {
		return false
	}

	if !m.Header.equal(otherMsg.Header) {
		return false
	}

	switch m.Type {
	case MessageTypeKeyGen2:
		if m.KeyGen2 != nil && otherMsg.KeyGen2 != nil {
			if !m.KeyGen2.equal(otherMsg.KeyGen2) {
				return false
			}
		}

		fallthrough
	case MessageTypeKeyGen1:
		if m.KeyGen1 != nil && otherMsg.KeyGen1 != nil {
			return m.KeyGen1.equal(otherMsg.KeyGen1)
		}
		//case MessageTypeSign1:
		//	if m.Sign1 != nil && otherMsg.Sign1 != nil {
		//		return m.Sign1.Equal(otherMsg.Sign1)
		//	}
		//case MessageTypeSign2:
		//	if m.Sign2 != nil && otherMsg.Sign2 != nil {
		//		return m.Sign2.Equal(otherMsg.Sign2)
		//	}
	}
	return false
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

func (m *KeyGen1) size() int {
	return m.Proof.Size() + m.Commitments.Size()
}

func (m *KeyGen1) equal(other interface{}) bool {
	otherMsg, ok := other.(*KeyGen1)
	if !ok {
		return false
	}
	if !otherMsg.Proof.Equal(m.Proof) {
		return false
	}
	if !otherMsg.Commitments.Equal(m.Commitments) {
		return false
	}
	return true
}

const sizeKeygen2 = 32

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

func (m *KeyGen2) size() int {
	return sizeKeygen2
}

func (m *KeyGen2) equal(other interface{}) bool {
	otherMsg, ok := other.(*KeyGen2)
	if !ok {
		return false
	}
	if otherMsg.Share.Equal(&m.Share) != 1 {
		return false
	}
	return true
}
