// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ohttp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// KeyConfig is a key configuration as specified in RFC 9458. Key configs
// are serialized according to the format specified in section 3.1.
//
// It provides the information required by a client to encapsulate
// requests for a specific gateway.
//
// The RFC does not specify how the client acquires a key configuration,
// just its format.
type KeyConfig struct {
	KeyID               byte
	KemID               hpke.KEM
	PublicKey           kem.PublicKey
	SymmetricAlgorithms []SymmetricAlgorithm
}

// SymmetricAlgorithm is a pair of KDF and AEAD identifiers that a Gateway
// supports.
type SymmetricAlgorithm struct {
	KDFID  hpke.KDF
	AEADID hpke.AEAD
}

// MarshalBinary marshals the KeyConfig to the binary representations specified
// in the RFC.
func (k KeyConfig) MarshalBinary() ([]byte, error) {
	// HPKE Symmetric Algorithms {
	//   HPKE KDF ID (16),
	//   HPKE AEAD ID (16),
	// }
	//
	// Key Config {
	//   Key Identifier (8),
	//   HPKE KEM ID (16),
	//   HPKE Public Key (Npk * 8),
	//   HPKE Symmetric Algorithms Length (16) = 4..65532,
	//   HPKE Symmetric Algorithms (32) ...,
	// }

	pubKeyBLen := k.KemID.Scheme().PublicKeySize()
	algoBLen := len(k.SymmetricAlgorithms) * 4
	pubKeyB, err := k.PublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to binary: %w", err)
	}

	if len(pubKeyB) != pubKeyBLen {
		return nil, fmt.Errorf("unexpected marshalled public key length, wanted %d, got %d", pubKeyBLen, len(pubKeyB))
	}

	if algoBLen > math.MaxUint16 {
		return nil, fmt.Errorf("cannot encode symmetric algorithms byte length as uint16, got len %d", algoBLen)
	}

	out := make([]byte, 1+2+pubKeyBLen+2+algoBLen)
	out[0] = k.KeyID
	i := 1
	binary.BigEndian.PutUint16(out[i:i+2], uint16(k.KemID))
	i += 2
	copy(out[i:i+pubKeyBLen], pubKeyB)
	i += pubKeyBLen
	//nolint:gosec
	binary.BigEndian.PutUint16(out[i:i+2], uint16(algoBLen))
	i += 2
	for _, algo := range k.SymmetricAlgorithms {
		binary.BigEndian.PutUint16(out[i:i+2], uint16(algo.KDFID))
		i += 2
		binary.BigEndian.PutUint16(out[i:i+2], uint16(algo.AEADID))
		i += 2
	}

	return out, nil
}

// UnmarshalBinary unmarshals a key config from the binary representation specified in the RFC.
func (k *KeyConfig) UnmarshalBinary(b []byte) error {
	const (
		keyIDLen      = 1
		pubKeyLenLen  = 2
		kemLen        = 1
		symAlgoLenLen = 2
		minSymAlgoLen = 4 // 2 bytes KDF + 2 bytes AEAD
		minBLen       = keyIDLen + pubKeyLenLen + kemLen + symAlgoLenLen + minSymAlgoLen
	)
	if len(b) < minBLen {
		return fmt.Errorf("needs at least %d bytes but got %d", minBLen, len(b))
	}

	kc := KeyConfig{}
	kc.KeyID = b[0]
	b = b[1:]
	kc.KemID = hpke.KEM(binary.BigEndian.Uint16(b[:2]))
	if !kc.KemID.IsValid() {
		return errors.New("invalid KEM")
	}
	b = b[2:]

	pubKeyBLen := kc.KemID.Scheme().PublicKeySize()
	if len(b) < pubKeyBLen {
		return errors.New("missing public key")
	}

	pubKey, err := kc.KemID.Scheme().UnmarshalBinaryPublicKey(b[:pubKeyBLen])
	if err != nil {
		return fmt.Errorf("failed to unmarshal binary public key: %w", err)
	}
	kc.PublicKey = pubKey
	b = b[pubKeyBLen:]

	if len(b) < 2 {
		return errors.New("missing algorithms length")
	}

	algoBLen := binary.BigEndian.Uint16(b[0:2])
	b = b[2:]

	if len(b) < int(algoBLen) || algoBLen == 0 {
		return errors.New("incomplete symmetric algorithms")
	}

	if algoBLen%4 != 0 {
		return errors.New("algorithm length must be a multiple of 4")
	}

	algoLen := algoBLen / 4
	kc.SymmetricAlgorithms = make([]SymmetricAlgorithm, algoLen)
	for i := 0; i < int(algoLen); i++ {
		algo := SymmetricAlgorithm{
			KDFID:  hpke.KDF(binary.BigEndian.Uint16(b[0:2])),
			AEADID: hpke.AEAD(binary.BigEndian.Uint16(b[2:4])),
		}
		if !algo.KDFID.IsValid() || !algo.AEADID.IsValid() {
			return fmt.Errorf("invalid symetric algorithms at position %d", i)
		}

		kc.SymmetricAlgorithms[i] = algo
		b = b[4:]
	}

	*k = kc

	return nil
}

func (k KeyConfig) valid() error {
	if !k.KemID.IsValid() {
		return errors.New("invalid KEM")
	}

	if len(k.SymmetricAlgorithms) == 0 {
		return errors.New("missing a symmetric algorithm")
	}

	for i, algo := range k.SymmetricAlgorithms {
		if !algo.KDFID.IsValid() {
			return fmt.Errorf("invalid KDF in item %d", i)
		}
		if !algo.AEADID.IsValid() {
			return fmt.Errorf("invalid KDF in item %d", i)
		}
	}

	return nil
}

// KeyConfigs is a list key of configurations as specified in RFC 9458.
//
// These key configurations are serialized to the application/ohttp-keys format
// specified in section 3.2 of the RFC.
type KeyConfigs []KeyConfig

// MarshalBinary marshals the key configurations to binary application/ohttp-keys format.
func (k KeyConfigs) MarshalBinary() ([]byte, error) {
	// Per the RFC:
	//
	// Each encoded configuration is prefixed with a 2-byte integer in
	// network byte order that indicates the length of the key configuration
	// in bytes. The length-prefixed encodings are concatenated to form a list.
	items := make([][]byte, 0, len(k))
	total := 0
	for i, kc := range k {
		b, err := kc.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal key config %d: %w", i, err)
		}
		items = append(items, b)
		total += len(b)
	}

	out := make([]byte, total+len(k)*2)
	i := 0
	for _, item := range items {
		itemLen := len(item)
		if itemLen > math.MaxInt16 {
			return nil, fmt.Errorf("length of key config for key id %d overflows uint16", item[0])
		}

		binary.BigEndian.PutUint16(out[i:i+2], uint16(itemLen))
		i += 2

		copy(out[i:i+itemLen], item)
		i += itemLen
	}

	return out, nil
}

// UnmarshalBinary unmarshals the key configurations from the application/ohttp-keys binary format.
func (k *KeyConfigs) UnmarshalBinary(p []byte) error {
	kcs := make(KeyConfigs, 0)
	for len(p) > 0 {
		if len(p) < 2 {
			return errors.New("missing length")
		}

		kcLen := binary.BigEndian.Uint16(p[:2])
		p = p[2:]

		if len(p) < int(kcLen) {
			return fmt.Errorf("want data of at least len %d, got %d", kcLen, len(p))
		}

		var kc KeyConfig
		err := kc.UnmarshalBinary(p[:kcLen])
		if err != nil {
			return err
		}
		p = p[kcLen:]

		kcs = append(kcs, kc)
	}

	*k = kcs

	return nil
}
