package polynomial

import (
	"crypto/rand"
	"fmt"

	"github.com/bartke/threshold-signatures-ed25519/party"
	"github.com/bartke/threshold-signatures-ed25519/ristretto"
)

type Polynomial struct {
	coefficients []ristretto.Scalar
}

// NewPolynomial generates a Polynomial f(X) = secret + a1*X + ... + at*X^t,
// with coefficients in Z_q, and degree t.
func NewPolynomial(degree party.Size, constant *ristretto.Scalar) *Polynomial {
	var polynomial Polynomial
	polynomial.coefficients = make([]ristretto.Scalar, degree+1)

	// SetWithoutSelf the constant term to the secret
	polynomial.coefficients[0].Set(constant)

	var err error
	randomBytes := make([]byte, 64)
	for i := party.Size(1); i <= degree; i++ {
		_, err = rand.Read(randomBytes)
		if err != nil {
			panic(fmt.Errorf("edwards25519: failed to generate random Scalar: %w", err))
		}
		_, _ = polynomial.coefficients[i].SetUniformBytes(randomBytes)
	}

	return &polynomial
}

// Evaluate evaluates a polynomial in a given variable index
// We use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Evaluate(index *ristretto.Scalar) *ristretto.Scalar {
	if index.Equal(ristretto.NewScalar()) == 1 {
		panic("attempt to leak secret")
	}

	var result ristretto.Scalar
	// reverse order
	for i := len(p.coefficients) - 1; i >= 0; i-- {
		// b_n-1 = b_n * x + a_n-1
		result.MultiplyAdd(&result, index, &p.coefficients[i])
	}
	return &result
}

func (p *Polynomial) Constant() *ristretto.Scalar {
	var result ristretto.Scalar
	result.Set(&p.coefficients[0])
	return &result
}

// Degree is the highest power of the Polynomial
func (p *Polynomial) Degree() party.Size {
	return party.Size(len(p.coefficients)) - 1
}

// Size is the number of coefficients of the polynomial
// It is equal to Degree+1
func (p *Polynomial) Size() int {
	return len(p.coefficients)
}

// Reset sets all coefficients to 0
func (p *Polynomial) Reset() {
	zero := ristretto.NewScalar()
	for i := range p.coefficients {
		p.coefficients[i].Set(zero)
	}
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (p *Polynomial) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, 0, p.Size())
	return p.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (p *Polynomial) UnmarshalBinary(data []byte) error {
	degree, err := party.FromBytes(data)
	if err != nil {
		return err
	}
	coefficientCount := degree + 1
	remaining := data[party.IDByteSize:]

	count := len(remaining)
	if count%32 != 0 {
		return fmt.Errorf("length of data is wrong")
	}
	if count != int(coefficientCount)*32 {
		return fmt.Errorf("wrong number of coefficients embedded")
	}

	p.coefficients = make([]ristretto.Scalar, coefficientCount)
	for i := 0; i < int(coefficientCount); i++ {
		_, err = p.coefficients[i].SetCanonicalBytes(remaining[i*32 : (i+1)*32])
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Polynomial) BytesAppend(existing []byte) ([]byte, error) {
	existing = append(existing, p.Degree().Bytes()...)
	for i := 0; i < len(p.coefficients); i++ {
		existing = append(existing, p.coefficients[i].Bytes()...)
	}
	return existing, nil
}
