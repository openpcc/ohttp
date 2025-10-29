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

package ohttp_test

import (
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/ohttp"
	"github.com/stretchr/testify/require"
)

func TestKeyConfigMarshalUnmarshalBinary(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pubKey, _, err := hpke.KEM_P256_HKDF_SHA256.Scheme().GenerateKeyPair()
		require.NoError(t, err)

		kc := ohttp.KeyConfig{
			KeyID:     0,
			KemID:     hpke.KEM_P256_HKDF_SHA256,
			PublicKey: pubKey,
			SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
				{
					KDFID:  hpke.KDF_HKDF_SHA256,
					AEADID: hpke.AEAD_AES128GCM,
				},
				{
					KDFID:  hpke.KDF_HKDF_SHA384,
					AEADID: hpke.AEAD_AES256GCM,
				},
			},
		}

		b, err := kc.MarshalBinary()
		require.NoError(t, err)

		var got ohttp.KeyConfig
		err = got.UnmarshalBinary(b)
		require.NoError(t, err)

		require.Equal(t, kc, got)
	})

	t.Run("ok, example from RFC", func(t *testing.T) {
		kemID := hpke.KEM_X25519_HKDF_SHA256

		privKeyB, err := hex.DecodeString(`3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a`)
		require.NoError(t, err)

		privKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(privKeyB)
		require.NoError(t, err)

		b, err := hex.DecodeString(`01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003`)
		require.NoError(t, err)

		kc := ohttp.KeyConfig{
			KeyID:     1,
			KemID:     hpke.KEM_X25519_HKDF_SHA256,
			PublicKey: privKey.Public(),
			SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
				{
					KDFID:  hpke.KDF_HKDF_SHA256,
					AEADID: hpke.AEAD_AES128GCM,
				},
				{
					KDFID:  hpke.KDF_HKDF_SHA256,
					AEADID: hpke.AEAD_ChaCha20Poly1305,
				},
			},
		}

		var got ohttp.KeyConfig
		err = got.UnmarshalBinary(b)
		require.NoError(t, err)
		require.Equal(t, kc, got)

		gotB, err := got.MarshalBinary()
		require.NoError(t, err)

		require.Equal(t, b, gotB)
	})

	unmarshalFailTests := map[string]func([]byte) []byte{
		"empty byte slice": func(b []byte) []byte {
			return []byte{}
		},
		"nil byte slice": func(b []byte) []byte {
			return nil
		},
		"invalid kem ID": func(b []byte) []byte {
			b[1] = 0
			b[2] = 0
			return b
		},
		"invalid KDF ID": func(b []byte) []byte {
			b[41] = 0
			b[42] = 0
			return b
		},
		"invalid AEAD ID": func(b []byte) []byte {
			b[43] = 0
			b[44] = 0
			return b
		},
	}
	for name, modFunc := range unmarshalFailTests {
		t.Run(name, func(t *testing.T) {
			b, err := hex.DecodeString(`01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003`)
			require.NoError(t, err)

			b = modFunc(b)

			var got ohttp.KeyConfig
			err = got.UnmarshalBinary(b)
			require.Error(t, err)
		})
	}

	t.Run("fail, no panics", func(t *testing.T) {
		b, err := hex.DecodeString(`01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003`)
		require.NoError(t, err)

		// will succeed at len(b)+1, so test all options before that.
		for i := range len(b) {
			in := b[:i]
			var got ohttp.KeyConfig
			err := got.UnmarshalBinary(in)
			require.Error(t, err)
		}
	})
}

func TestKeyConfigs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pubKey, _, err := hpke.KEM_P256_HKDF_SHA256.Scheme().GenerateKeyPair()
		require.NoError(t, err)

		kcs := ohttp.KeyConfigs{
			{
				KeyID:     0,
				KemID:     hpke.KEM_P256_HKDF_SHA256,
				PublicKey: pubKey,
				SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
					{
						KDFID:  hpke.KDF_HKDF_SHA256,
						AEADID: hpke.AEAD_AES128GCM,
					},
					{
						KDFID:  hpke.KDF_HKDF_SHA384,
						AEADID: hpke.AEAD_AES256GCM,
					},
				},
			},
			{
				KeyID:     1,
				KemID:     hpke.KEM_P256_HKDF_SHA256,
				PublicKey: pubKey,
				SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
					{
						KDFID:  hpke.KDF_HKDF_SHA256,
						AEADID: hpke.AEAD_AES128GCM,
					},
					{
						KDFID:  hpke.KDF_HKDF_SHA384,
						AEADID: hpke.AEAD_AES256GCM,
					},
				},
			},
		}

		b, err := kcs.MarshalBinary()
		require.NoError(t, err)

		var got ohttp.KeyConfigs
		err = got.UnmarshalBinary(b)
		require.NoError(t, err)

		require.Equal(t, kcs, got)
	})
}
