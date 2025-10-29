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
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/ohttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T, transportOpts []ohttp.TransportOption, wrapInMiddleware bool, handler http.Handler, opts ...ohttp.GatewayOption) *ohttp.Transport {
	t.Helper()

	kemID := hpke.KEM_P256_HKDF_SHA256
	pubKey, privKey, err := kemID.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	keyPair := ohttp.KeyPair{
		SecretKey: privKey,
		KeyConfig: ohttp.KeyConfig{
			KeyID:     1,
			KemID:     kemID,
			PublicKey: pubKey,
			SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
				{
					KDFID:  hpke.KDF_HKDF_SHA256,
					AEADID: hpke.AEAD_AES128GCM,
				},
			},
		},
	}

	if wrapInMiddleware {
		gateway, err := ohttp.NewGateway(keyPair, opts...)
		require.NoError(t, err)

		handler = ohttp.Middleware(gateway, handler)
	}

	gatewayURL := runHandlerWhile(t, handler)

	// Talk directly to the gateway, should not happen in reality, but skipped the relay
	// will not matter for the logic of these tests.
	transport, err := ohttp.NewTransport(keyPair.KeyConfig, gatewayURL, transportOpts...)
	require.NoError(t, err)

	return transport
}

type roundtripTest struct {
	outerRequestChunked  bool
	outerResponseChunked bool
	reqFunc              func(t *testing.T, serverURL string) *http.Request
	handleFunc           func(t *testing.T, w http.ResponseWriter, r *http.Request)
	verifyRespFunc       func(t *testing.T, resp *http.Response)
}

func (rt roundtripTest) newRequest(t *testing.T, serverURL string) *http.Request {
	t.Helper()

	if rt.reqFunc != nil {
		return rt.reqFunc(t, serverURL)
	}

	// create a simple GET request if no custom request is provided.
	req, err := http.NewRequest(http.MethodGet, serverURL, nil)
	require.NoError(t, err)

	return req
}

func (rt roundtripTest) verifyResp(t *testing.T, resp *http.Response) {
	t.Helper()

	require.NotNil(t, resp)
	if rt.verifyRespFunc != nil {
		rt.verifyRespFunc(t, resp)
	}
}

type chunkReader struct {
	sleep     time.Duration
	chunkLen  int
	remaining int
	reader    io.Reader
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		time.Sleep(r.sleep)
		r.remaining = r.chunkLen
	}

	n := min(len(p), r.remaining)
	rn, err := r.reader.Read(p[:n])
	r.remaining -= rn
	return rn, err
}

type closingReader struct {
	closeFunc func() error
	reader    io.Reader
}

func (r *closingReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *closingReader) Close() error {
	if r.closeFunc == nil {
		return nil
	}
	return r.closeFunc()
}

func assertChunkTiming(t *testing.T, r io.Reader, chunkLen int) {
	t.Helper()

	lastRead := time.Now()
	for i := 0; ; i++ {
		got := make([]byte, chunkLen)
		n, err := io.ReadFull(r, got)
		if errors.Is(err, io.EOF) {
			break
		}
		assert.NoError(t, err)
		assert.Equal(t, chunkLen, n)

		if i > 0 {
			now := time.Now()
			t.Log(now)
			passed := now.Sub(lastRead)
			assert.Greater(t, passed.Milliseconds(), int64(0))
			lastRead = now
		}
	}
}
