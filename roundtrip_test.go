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
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidentsecurity/ohttp"
	"github.com/confidentsecurity/twoway"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransportGatewayRoundtrip(t *testing.T) {
	t.Run("fail, only allowlisted hostnames allowed by default", func(t *testing.T) {
		called := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		transport := setup(t, nil, true, handler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		_, err = transport.RoundTrip(req)
		require.Error(t, err)

		// make sure the handler was not called.
		require.False(t, called)
	})

	t.Run("ok, empty hostname allowed with nil validator", func(t *testing.T) {
		called := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		transport := setup(t, nil, true, handler, ohttp.WithRequestValidator(nil))

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		_, err = transport.RoundTrip(req)
		require.NoError(t, err)

		// make sure the handler was called.
		require.True(t, called)
	})

	gatewayErrorResponses := map[string]struct {
		reqFunc                func(t *testing.T) *http.Request
		handlerFunc            func(t *testing.T, w http.ResponseWriter, r *http.Request)
		modOHTTPReqFunc        func(t *testing.T, r *http.Request)
		modOHTTPRespFunc       func(t *testing.T, resp *http.Response)
		wantResponseStatusCode int
	}{
		"fail, unknown key id": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				// first byte in the header is the key id.
				body[0]++
				r.Body = io.NopCloser(bytes.NewReader(body))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"fail, unchunked, empty body": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				r.ContentLength = 0
				r.Body = io.NopCloser(strings.NewReader(""))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"fail, chunked, empty body": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.ContentLength = -1 // make this a chunked request.
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				r.Body = io.NopCloser(bytes.NewReader([]byte{}))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"fail, unchunked, incomplete header in body": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				r.ContentLength = 3
				r.Body = io.NopCloser(io.LimitReader(r.Body, 3))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"fail, chunked, incomplete header in body": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.ContentLength = -1 // make this a chunked request.
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				r.ContentLength = 3
				r.Body = io.NopCloser(io.LimitReader(r.Body, 3))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"fail, unchunked, tampered with ciphertext": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				body[len(body)-1]++
				r.Body = io.NopCloser(bytes.NewReader(body))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"fail, chunked, first chunk ciphertext tampered with": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.ContentLength = -1 // make this a chunked request.
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)

				// determine where the chunk ciphertext begins
				offset := twoway.BinaryRequestHeaderLen + 65 // header + encapsulated key length
				chunkLen, err := quicvarint.Read(bytes.NewReader(body[offset:]))
				n := quicvarint.Len(chunkLen)
				require.NoError(t, err)

				body[offset+n+1]++ // tamper with the first byte of the ciphertext
				r.Body = io.NopCloser(bytes.NewReader(body))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// this short body will result in the encoded request fitting in a single chunk,
				// the chunk will be decoded as part of the decapsulation so it can be caught in the gateway.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		// TODO: Enable this test once bhttp uses the reader approach throughout the package.
		//
		// Due to the separate readAll goroutine in the bhttp package, we can't guarantee that this error will show up
		// in the inner handler, or in the gateway. Once we refactor the bhttp package to use the reader-approach we
		// can be sure the error will always show up in the handler.
		//"fail, chunked, later chunk ciphertext tampered with": {
		//	reqFunc: func(t *testing.T) *http.Request {
		//		body := bytes.Repeat([]byte("a"), 4096) // default send chunk length in bhttp encoding.
		//		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", bytes.NewReader(body))
		//		req.ContentLength = -1
		//		require.NoError(t, err)
		//		return req
		//	},
		//	modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
		//		body, err := io.ReadAll(r.Body)
		//		require.NoError(t, err)
		//		body[len(body)-1]++
		//		r.Body = io.NopCloser(bytes.NewReader(body))
		//	},
		//	handlerFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
		//		// Due to chunked bodies being opened and decoded as the chunks arrive, this will result in a handler-level error.
		//		// There's no way around this, as we don't know if the target service might already have began writing a response.
		//		_, err := io.ReadAll(r.Body)
		//		assert.Error(t, err)
		//		w.WriteHeader(http.StatusBadRequest)
		//	},
		//	modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
		//		require.Equal(t, http.StatusOK, resp.StatusCode)
		//	},
		//},
		"fail, unchunked request, chunked media type": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				r.Header.Set("Content-Type", ohttp.ChunkedRequestMediaType)
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"fail, chunked request, unchunked media type": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				r.Header.Set("Content-Type", ohttp.ChunkedRequestMediaType)
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"ok, unchunked request, chunked media type": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			modOHTTPReqFunc: func(t *testing.T, r *http.Request) {
				r.Header.Set("Content-Type", ohttp.ChunkedRequestMediaType)
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				// not modifying anything, just verifying the status code.
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
			wantResponseStatusCode: http.StatusBadRequest,
		},
		"fail, unchunked response, chunked media type": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			handlerFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("hello world!"))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				resp.Header.Set("Content-Type", ohttp.ChunkedResponseMediaType)
			},
		},
		"fail, chunked response, unchunked media type": {
			reqFunc: func(t *testing.T) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://ohttp.invalid", strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			handlerFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Transfer-Encoding", "chunked")
				w.Write([]byte("hello world!"))
			},
			modOHTTPRespFunc: func(t *testing.T, resp *http.Response) {
				resp.Header.Set("Content-Type", ohttp.ResponseMediaType)
			},
		},
	}

	for name, tc := range gatewayErrorResponses {
		t.Run(name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.handlerFunc == nil {
					assert.Fail(t, "unexpected call to handler")
					return
				}
				tc.handlerFunc(t, w, r)
			})

			innerClient := &http.Client{
				Timeout: 15 * time.Second,
				Transport: &tamperingTransport{
					orig: http.DefaultTransport,
					modReq: func(req *http.Request) {
						if tc.modOHTTPReqFunc != nil {
							tc.modOHTTPReqFunc(t, req)
						}
					},
					modResp: func(resp *http.Response) {
						if tc.modOHTTPRespFunc != nil {
							tc.modOHTTPRespFunc(t, resp)
						}
					},
				},
			}

			transport := setup(t, []ohttp.TransportOption{ohttp.WithHTTPClient(innerClient)}, true, handler)

			client := http.Client{
				Timeout:   15 * time.Second,
				Transport: transport,
			}

			_, err := client.Do(tc.reqFunc(t))

			require.Error(t, err)

			if tc.wantResponseStatusCode != 0 {
				var responseStatusErr ohttp.ResponseStatusError
				require.ErrorAs(t, err, &responseStatusErr)
				require.Equal(t, responseStatusErr.StatusCode, tc.wantResponseStatusCode)
			}
		})
	}
}

func runHandlerWhile(t *testing.T, handler http.Handler) string {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(func() {
		server.Close()
	})

	return server.URL
}

func requireReadAll(t *testing.T, rc io.ReadCloser, want string) {
	t.Helper()

	got, err := io.ReadAll(rc)
	require.NoError(t, err)

	require.Equal(t, want, string(got))
}

func assertReadAll(t *testing.T, rc io.ReadCloser, want string) {
	t.Helper()

	got, err := io.ReadAll(rc)
	assert.NoError(t, err)

	assert.Equal(t, want, string(got))
}

type verifyingTransport struct {
	orig           http.RoundTripper
	verifyResponse func(resp *http.Response)
}

func (t *verifyingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.orig.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	if t.verifyResponse != nil {
		t.verifyResponse(resp)
	}

	return resp, nil
}

type tamperingTransport struct {
	orig    http.RoundTripper
	modReq  func(r *http.Request)
	modResp func(r *http.Response)
}

func (t *tamperingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.modReq != nil {
		t.modReq(req)
	}
	resp, err := t.orig.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if t.modResp != nil {
		t.modResp(resp)
	}
	return resp, nil
}
