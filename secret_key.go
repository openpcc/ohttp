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
	"context"
	"errors"
	"slices"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/confidentsecurity/twoway"
)

var (
	errorKeyNotFound     = errors.New("key not found")
	ErrorKeyNotYetActive = errors.New("key not yet active")
	ErrorKeyExpired      = errors.New("key expired")
)

// SecretKeyFinder finds secret key info for a given request header.
//
// This allows the Gateway to find appropriate keys on-demand before a
// request is decapsulated.
type SecretKeyFinder interface {
	FindSecretKey(ctx context.Context, header twoway.RequestHeader) (SecretKeyInfo, error)
}

// SecretKeyInfo holds the identity and suite information for a private key.
type SecretKeyInfo struct {
	KeyID byte
	Suite twoway.HPKESuite
	Key   kem.PrivateKey
}

// Keypair combines a private key with its [KeyConfig]. Can be provided as a [SecretKeyFinder]
// to a Gateway. Suites are constructed as circl/hpke suites.
type KeyPair struct {
	SecretKey kem.PrivateKey
	KeyConfig KeyConfig
}

// FindSecretKey checks if the keypair matches the given header and returns appropriate info if it does.
func (k KeyPair) FindSecretKey(_ context.Context, header twoway.RequestHeader) (SecretKeyInfo, error) {
	if header.KeyID != k.KeyConfig.KeyID || header.KemID != k.KeyConfig.KemID {
		return SecretKeyInfo{}, errorKeyNotFound
	}

	found := slices.ContainsFunc(k.KeyConfig.SymmetricAlgorithms, func(a SymmetricAlgorithm) bool {
		return a.KDFID == header.KDFID && a.AEADID == header.AEADID
	})
	if !found {
		return SecretKeyInfo{}, errorKeyNotFound
	}

	suite := hpke.NewSuite(header.KemID, header.KDFID, header.AEADID)
	return SecretKeyInfo{
		KeyID: k.KeyConfig.KeyID,
		Suite: twoway.AdaptCirclHPKESuite(suite),
		Key:   k.SecretKey,
	}, nil
}
