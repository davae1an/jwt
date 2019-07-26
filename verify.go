package jwt

import (
	"bytes"
	"errors"
)

// ErrAlgValidation indicates an incoming JWT's "alg" field mismatches the Validator's.
var ErrAlgValidation = errors.New(`"alg" field mismatch`)

// VerifyOption is a functional option for verifying.
type VerifyOption func(*RawToken) error

// ParseToken parses a byte slice representing a JWT and returns a raw JWT,
// which can be verified and decoded into a struct that implements Token.
func ParseToken(token []byte, alg Algorithm) (RawToken, error) {
	rt := &RawToken{
		alg: alg,
	}

	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 {
		return *rt, ErrMalformed
	}

	cbytes := token[sep1+1:]
	sep2 := bytes.IndexByte(cbytes, '.')
	if sep2 < 0 {
		return *rt, ErrMalformed
	}
	rt.setToken(token, sep1, sep2)
	return *rt, nil
}

// DecodeToken decodes a raw JWT into a header and a payload.
func (r RawToken) DecodeToken(payload interface{}) error {
	// // Next, unmarshal the token accordingly.
	// var (
	// 	enc      []byte // encoded header/payload
	// 	dec      []byte // decoded header/payload
	// 	encoding = base64.RawURLEncoding
	// 	err      error
	// )
	// // Header.
	// enc = r.header()
	// dec = make([]byte, encoding.DecodedLen(len(enc)))
	// if _, err = encoding.Decode(dec, enc); err != nil {
	// 	return err
	// }
	// if err = json.Unmarshal(dec, h); err != nil {
	// 	return err
	// }
	// // Claims.
	// enc = r.claims()
	// dec = make([]byte, encoding.DecodedLen(len(enc)))
	// if _, err = encoding.Decode(dec, enc); err != nil {
	// 	return err
	// }
	// if err = json.Unmarshal(dec, payload); err != nil {
	// 	return err
	// }
	// return nil

	var err error
	if err = r.decodeHeader(); err != nil {
		return err
	}
	if rv, ok := r.alg.(Resolver); ok {
		if err = rv.Resolve(r.hd); err != nil {
			return err
		}
	}

	return r.decode(payload)
}

// Verify verifies a token's signature using alg. Before verification, opts is iterated and
// each option in it is run.
func Verify(token []byte, alg Algorithm, payload interface{}, opts ...VerifyOption) (Header, error) {
	rt := &RawToken{
		alg: alg,
	}

	sep1 := bytes.IndexByte(token, '.')
	if sep1 < 0 {
		return rt.hd, ErrMalformed
	}

	cbytes := token[sep1+1:]
	sep2 := bytes.IndexByte(cbytes, '.')
	if sep2 < 0 {
		return rt.hd, ErrMalformed
	}
	rt.setToken(token, sep1, sep2)

	var err error
	if err = rt.decodeHeader(); err != nil {
		return rt.hd, err
	}
	if rv, ok := alg.(Resolver); ok {
		if err = rv.Resolve(rt.hd); err != nil {
			return rt.hd, err
		}
	}
	for _, opt := range opts {
		if err = opt(rt); err != nil {
			return rt.hd, err
		}
	}
	if err = alg.Verify(rt.headerPayload(), rt.sig()); err != nil {
		return rt.hd, err
	}
	return rt.hd, rt.decode(payload)
}

// ValidateHeader checks whether the algorithm contained
// in the JOSE header is the same used by the algorithm.
func ValidateHeader(rt *RawToken) error {
	if rt.alg.Name() != rt.hd.Algorithm {
		return ErrAlgValidation
	}
	return nil
}

// ValidatePayload runs validators against a Payload after it's been decoded.
func ValidatePayload(pl *Payload, vds ...Validator) VerifyOption {
	return func(rt *RawToken) error {
		rt.pl = pl
		rt.vds = vds
		return nil
	}
}

// Compile-time checks.
var _ VerifyOption = ValidateHeader
