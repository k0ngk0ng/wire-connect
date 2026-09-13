// Package secure contains the authenticated pairing and session primitives
// used by the connect command.
package secure

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	codeLength       = 12
	codeRoomLength   = 4
	codeSecretLength = codeLength - codeRoomLength
)

// Crockford's alphabet is deliberately reduced to characters that are easy to
// distinguish when read aloud or copied from a terminal. In particular, I, L,
// O and U are omitted.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Code is a one-time pairing code. The first four characters are the public
// room identifier; the remaining eight characters are the PAKE password.
//
// A Code value has no exported fields so callers cannot accidentally construct
// a value which bypasses ParseCode's validation.
type Code struct {
	raw [codeLength]byte
}

var (
	errInvalidCode = errors.New("wire-connect: invalid pairing code")
	errWeakCode    = errors.New("wire-connect: pairing code is too weak")
)

// GenerateCode returns a cryptographically random pairing code. It uses 60
// random bits and rejects the small set of human-obvious weak patterns.
func GenerateCode() (Code, error) {
	for range 32 {
		var random [8]byte
		if _, err := io.ReadFull(cryptorand.Reader, random[:]); err != nil {
			return Code{}, fmt.Errorf("wire-connect: generate pairing code: %w", err)
		}

		// Eight bytes provide 64 bits. Discarding four bits gives exactly twelve
		// uniformly distributed five-bit symbols.
		var value uint64
		for _, b := range random {
			value = value<<8 | uint64(b)
		}
		value >>= 4

		var code Code
		for i := codeLength - 1; i >= 0; i-- {
			code.raw[i] = codeAlphabet[value&31]
			value >>= 5
		}
		if !weakSecret(code.raw[codeRoomLength:]) {
			return code, nil
		}
	}

	return Code{}, errors.New("wire-connect: random pairing code generation repeatedly produced a weak value")
}

// ParseCode parses a code printed by Code.String. ASCII lower case is
// accepted, and hyphens or ASCII whitespace may be inserted for readability.
func ParseCode(input string) (Code, error) {
	var normalized [codeLength]byte
	n := 0
	for i := 0; i < len(input); i++ {
		b := input[i]
		switch b {
		case '-', ' ', '\t', '\r', '\n':
			continue
		}
		if b >= 'a' && b <= 'z' {
			b -= 'a' - 'A'
		}
		if !isCodeCharacter(b) || n >= len(normalized) {
			return Code{}, errInvalidCode
		}
		normalized[n] = b
		n++
	}
	if n != len(normalized) {
		return Code{}, errInvalidCode
	}
	if weakSecret(normalized[codeRoomLength:]) {
		return Code{}, errWeakCode
	}

	return Code{raw: normalized}, nil
}

// String returns the canonical code grouped into three lower-case blocks of
// four characters. ParseCode accepts either case, but the lower-case form is
// also the form used by the rendezvous room API.
func (c Code) String() string {
	if !c.valid() {
		return ""
	}
	var out [codeLength + 2]byte
	copy(out[0:4], c.raw[0:4])
	out[4] = '-'
	copy(out[5:9], c.raw[4:8])
	out[9] = '-'
	copy(out[10:14], c.raw[8:12])
	return strings.ToLower(string(out[:]))
}

// Room returns the canonical lower-case public four-character room
// identifier. It returns an empty string for an invalid zero Code.
func (c Code) Room() string {
	if !c.valid() {
		return ""
	}
	return strings.ToLower(string(c.raw[:codeRoomLength]))
}

func (c Code) valid() bool {
	for _, b := range c.raw {
		if !isCodeCharacter(b) {
			return false
		}
	}
	return !weakSecret(c.raw[codeRoomLength:])
}

func (c Code) secretBytes() []byte {
	return append([]byte(nil), c.raw[codeRoomLength:]...)
}

func isCodeCharacter(b byte) bool {
	return strings.IndexByte(codeAlphabet, b) >= 0
}

func crockfordIndex(b byte) int {
	return strings.IndexByte(codeAlphabet, b)
}

func weakSecret(secret []byte) bool {
	if len(secret) != codeSecretLength {
		return true
	}

	allSame := true
	for i := 1; i < len(secret); i++ {
		if secret[i] != secret[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	// Reject repeated blocks, as well as monotonic strings that are easy to
	// guess when a code is dictated manually.
	for blockLen := 1; blockLen <= len(secret)/2; blockLen++ {
		if len(secret)%blockLen != 0 {
			continue
		}
		repeated := true
		for i := blockLen; i < len(secret); i++ {
			if secret[i] != secret[i%blockLen] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}

	first := crockfordIndex(secret[0])
	if first >= 0 {
		ascending, descending := true, true
		for i := 1; i < len(secret); i++ {
			current := crockfordIndex(secret[i])
			if current < 0 {
				return true
			}
			if current != (first+i)%len(codeAlphabet) {
				ascending = false
			}
			if current != (first-i+len(codeAlphabet))%len(codeAlphabet) {
				descending = false
			}
		}
		if ascending || descending {
			return true
		}
	}

	// A few common hand-entered values deserve an explicit rejection even if
	// they do not fit one of the structural rules above.
	switch string(secret) {
	case "12345678", "87654321", "ABCDEFGH", "HGFEDCBA", "PASSWORD":
		return true
	default:
		return false
	}
}
