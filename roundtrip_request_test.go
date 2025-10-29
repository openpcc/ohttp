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
	"context"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/confidentsecurity/ohttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundtripRequest(t *testing.T) {
	tests := map[string]roundtripTest{
		"implicit get": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				req.Method = ""
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(0), r.ContentLength)
				assertReadAll(t, r.Body, "")
			},
		},
		"explicit get": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(0), r.ContentLength)
				assertReadAll(t, r.Body, "")
			},
		},
		"options request to non-star url": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodOptions, serverURL, nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodOptions, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(0), r.ContentLength)
				assertReadAll(t, r.Body, "")
			},
		},
		"implicit unchunked body, string reader": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, strings.NewReader("hello world!"))
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"User-Agent":     []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(12), r.ContentLength)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"implicit unchunked body, bytes reader": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, bytes.NewReader([]byte("hello world!")))
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"User-Agent":     []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(12), r.ContentLength)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"implicit unchunked body, bytes buffer": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				buf := bytes.NewBufferString("hello world!")
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, buf)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"User-Agent":     []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.NotNil(t, r.Body)
				assert.Equal(t, int64(12), r.ContentLength)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"explicit unchunked body, content-length set": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				r := io.MultiReader(strings.NewReader("hello world!")) // wrap in multireader so new request doesn't detect content-length.
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, r)
				require.NoError(t, err)
				req.ContentLength = 12
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"User-Agent":     []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.NotNil(t, r.Body)
				assert.Equal(t, int64(12), r.ContentLength)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"explicit unchunked body, .TransferEncoding gzip is stripped": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				r := io.MultiReader(strings.NewReader("hello world!")) // wrap in multireader so new request doesn't detect content-length.
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, r)
				require.NoError(t, err)
				req.ContentLength = 12
				req.TransferEncoding = []string{"gzip"}
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"User-Agent":     []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.NotNil(t, r.Body)
				assert.Equal(t, int64(12), r.ContentLength)
				assert.Equal(t, []string(nil), r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"explicit unchunked body, .TransferEncoding gzip is stripped even when followed by chunked": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				r := io.MultiReader(strings.NewReader("hello world!")) // wrap in multireader so new request doesn't detect content-length.
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, r)
				require.NoError(t, err)
				req.ContentLength = 12
				req.TransferEncoding = []string{"gzip", "chunked"}
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"User-Agent":     []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.NotNil(t, r.Body)
				assert.Equal(t, int64(12), r.ContentLength)
				assert.Equal(t, []string(nil), r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"implicit chunked body, non-fixed-length reader": {
			outerRequestChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				r := io.MultiReader(strings.NewReader("hello world!")) // wrap in multireader so new request doesn't detect content-length.
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, r)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(-1), r.ContentLength)
				assert.Equal(t, []string{"chunked"}, r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"implicit chunked body due to content-length 0": {
			outerRequestChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.ContentLength = 0
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(-1), r.ContentLength)
				assert.Equal(t, []string{"chunked"}, r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"explicit chunked body due to content-length -1": {
			outerRequestChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.ContentLength = -1
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(-1), r.ContentLength)
				assert.Equal(t, []string{"chunked"}, r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"explicit chunked body due to transfer-encoding": {
			outerRequestChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.TransferEncoding = []string{"chunked"}
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.NotNil(t, r.Body)
				assert.Equal(t, int64(-1), r.ContentLength)
				assert.Equal(t, []string{"chunked"}, r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"explicit chunked body due to transfer-encoding, gzip is stripped": {
			outerRequestChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.TransferEncoding = []string{"chunked", "gzip"}
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.NotNil(t, r.Body)
				assert.Equal(t, int64(-1), r.ContentLength)
				assert.Equal(t, []string{"chunked"}, r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"unchunked, transfer-encoding header is stripped": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.Header.Set("Transfer-Encoding", "chunked")
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"User-Agent":     []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.NotNil(t, r.Body)
				assert.Equal(t, int64(12), r.ContentLength)
				assert.Equal(t, []string(nil), r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
			},
		},
		"explicit chunked body due to trailers": {
			outerRequestChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, strings.NewReader("hello world!"))
				require.NoError(t, err)
				req.ContentLength = -1 // trailers are only sent when content length is -1 or 0.
				req.Trailer = make(http.Header)
				req.Trailer["X-Custom"] = []string{"abc"}
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, int64(-1), r.ContentLength)
				assert.Equal(t, []string{"chunked"}, r.TransferEncoding)
				assertReadAll(t, r.Body, "hello world!")
				assert.Equal(t, http.Header{
					"X-Custom": []string{"abc"},
				}, r.Trailer)
			},
		},
		"host defaults to host from URL": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL+"/test-path", nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				// host header is stripped from header map.
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, "/test-path", r.URL.String())
				assert.Equal(t, "/test-path", r.RequestURI)
				assert.Regexp(t, "127.0.0.1:[0-9]+", r.Host)
			},
		},
		"host header is ignored": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL+"/test-path", nil)
				require.NoError(t, err)
				req.Header.Set("Host", "confsec.invalid")
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				// host header is stripped from header map.
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)
				assert.Equal(t, "/test-path", r.URL.String())
				assert.Equal(t, "/test-path", r.RequestURI)
				assert.Regexp(t, "127.0.0.1:[0-9]+", r.Host)
			},
		},
		"host field is forwarded as host header": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				// url is different from the host field.
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL+"/test-path", nil)
				require.NoError(t, err)
				req.Host = "confsec.invalid"
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				// host header is stripped from header map.
				assert.Equal(t, http.Header{
					"User-Agent": []string{"Go-http-client/1.1"},
				}, r.Header)

				// URL is parsed from request line.
				assert.Equal(t, "/test-path", r.URL.String())
				// Host field is taken from client request Host.
				assert.Equal(t, "confsec.invalid", r.Host)
			},
		},
		"user-agent header nil": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				req.Header["User-Agent"] = nil
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.Header{}, r.Header)
			},
		},
		"custom user-agent header": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				req.Header.Set("User-Agent", "abc")
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.Header{
					"User-Agent": []string{"abc"},
				}, r.Header)
			},
		},
		"custom header": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				req.Header.Set("X-Custom-Request", "abc")
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.Header{
					"X-Custom-Request": []string{"abc"},
					"User-Agent":       []string{"Go-http-client/1.1"},
				}, r.Header)
			},
		},
		"proto fields are set": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "HTTP/1.1", r.Proto)
				assert.Equal(t, 1, r.ProtoMajor)
				assert.Equal(t, 1, r.ProtoMinor)
			},
		},
		"form ignored on client side": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, nil)
				require.NoError(t, err)
				req.Form = make(url.Values)
				req.Form.Set("test", "abc")
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assertReadAll(t, r.Body, "")
			},
		},
		"postform ignored on client side": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, nil)
				require.NoError(t, err)
				req.PostForm = make(url.Values)
				req.PostForm.Set("test", "abc")
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assertReadAll(t, r.Body, "")
			},
		},
		"multipartform ignored on client side": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, nil)
				require.NoError(t, err)
				req.MultipartForm = &multipart.Form{
					Value: map[string][]string{},
				}
				req.MultipartForm.Value["test"] = []string{"abc"}
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assertReadAll(t, r.Body, "")
			},
		},
		"pattern is empty": {
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverURL, nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Pattern)
			},
		},
	}

	for name, tc := range tests {
		t.Run("http, "+name, func(t *testing.T) {
			// first check if this test works for the regular HTTP server and transport. We want to
			// to match the behaviour in the ohttp test case.
			serverURL := runHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.handleFunc(t, w, r)
			}))
			client := http.Client{
				Timeout: 15 * time.Second,
				Transport: &http.Transport{
					DisableCompression: true, // prevent the transport from adding the `Accept-Encoding: gzip` header.
				},
			}

			req := tc.newRequest(t, serverURL)
			resp, err := client.Do(req)
			// logging request host field and server url to debug flaky "TestRoundtripRequest/http,_host_field_is_used" test.
			require.NoError(t, err, "request host field: %s, serverURL: %s", req.Host, serverURL)
			defer func() {
				err = resp.Body.Close()
				require.NoError(t, err)
			}()

			tc.verifyResp(t, resp)
		})

		t.Run("ohttp, "+name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.handleFunc(t, w, r)
			})

			// disable request validator so we can provide requests with hostnames.
			list := ohttp.NewHostnameAllowlist("127.0.0.1:80", "confsec.invalid")
			transport := setup(t, nil, true, handler, ohttp.WithRequestValidator(list))

			client := http.Client{
				Timeout:   15 * time.Second,
				Transport: transport,
			}

			// provide a fake URL so we can check urls in the same way as for http.
			req := tc.newRequest(t, "http://127.0.0.1:80")
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() {
				err = resp.Body.Close()
				require.NoError(t, err)
			}()

			tc.verifyResp(t, resp)
		})

		t.Run("ohttp, relay request, "+name, func(t *testing.T) {
			called := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true

				assert.Equal(t, http.MethodPost, r.Method)
				if tc.outerRequestChunked {
					assert.Equal(t, int64(-1), r.ContentLength)
					assert.Equal(t, http.Header{
						"Content-Type":    []string{"message/ohttp-chunked-req"},
						"Accept-Encoding": []string{"gzip"},
						"Date":            []string{r.Header.Get("Date")},
						"Incremental":     []string{"?1"},
					}, r.Header)
				} else {
					assert.Greater(t, r.ContentLength, int64(0))
					assert.Equal(t, http.Header{
						"Content-Type":    []string{"message/ohttp-req"},
						"Content-Length":  []string{r.Header.Get("Content-Length")},
						"Accept-Encoding": []string{"gzip"},
						"Date":            []string{r.Header.Get("Date")},
					}, r.Header)
				}

				// ensure we can parse the date.
				_, err := time.Parse(http.TimeFormat, r.Header.Get("Date"))
				assert.NoError(t, err)
			})

			// note: we're not wrapping the handler in a gateway.
			transport := setup(t, nil, false, handler)

			// provide a fake URL so we can check urls in the same way as for http.
			req := tc.newRequest(t, "http://127.0.0.1:80")
			_, err := transport.RoundTrip(req)
			require.Error(t, err) // should error, we didn't even hit a gateway.

			// make sure the handler was called
			require.True(t, called)
		})
	}

	t.Run("ohttp, remote addr is empty", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Empty(t, r.RemoteAddr)
		})

		transport := setup(t, nil, true, handler)

		client := http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()
		require.NoError(t, err)
	})

	t.Run("ohttp, request body is closed", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		transport := setup(t, nil, true, handler)

		client := http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid", strings.NewReader("hello world!"))
		require.NoError(t, err)

		closed := false
		req.Body = &closingReader{
			reader: req.Body,
			closeFunc: func() error {
				closed = true
				return nil
			},
		}

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()

		require.True(t, closed)
	})

	t.Run("ohttp, chunked timing", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, int64(-1), r.ContentLength)
			assertChunkTiming(t, r.Body, 4096)
		})

		transport := setup(t, nil, true, handler)

		client := http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}

		bdy := &chunkReader{
			reader:   strings.NewReader(strings.Repeat("a", 4096*20)),
			chunkLen: 4096,
			sleep:    time.Millisecond * 50,
		}

		req, err := http.NewRequest(http.MethodPost, "http://ohttp.invalid", bdy)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()
	})

	t.Run("ohttp, chunked outer request, default settings", func(t *testing.T) {
		const (
			nrOfChunks              = 20
			maxBHTTPEncodedChunkLen = 4096
			userChunkLen            = maxBHTTPEncodedChunkLen - 2
			// OHTTP QUIC int length + AEAD overhead
			outChunkLen = maxBHTTPEncodedChunkLen + 2 + 16
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
		})

		// capture the raw bytes read from the connection.
		buf := bytes.NewBuffer(nil)
		httpClient := http.Client{
			Transport: &verifyingTransport{
				orig: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						conn, err := net.Dial(network, addr)
						if err != nil {
							return nil, err
						}
						return &captureConn{
							Conn:     conn,
							capWrite: buf,
						}, nil
					},
				},
			},
		}

		opts := []ohttp.TransportOption{
			ohttp.WithHTTPClient(&httpClient),
		}

		transport := setup(t, opts, true, handler)

		bdy := &chunkReader{
			reader:   strings.NewReader(strings.Repeat("a", 4096*20)),
			chunkLen: 4096,
			sleep:    0,
		}

		req, err := http.NewRequest(http.MethodPost, "http://ohttp.invalid", bdy)
		require.NoError(t, err)

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)

		err = resp.Body.Close()
		require.NoError(t, err)

		gotChunks := requireParseChunkLengths(t, buf.String())
		gotBodyChunks := 0
		for _, gotChunk := range gotChunks {
			if gotChunk == outChunkLen {
				gotBodyChunks++
			}
		}

		require.Equal(t, nrOfChunks, gotBodyChunks)
	})

	t.Run("ohttp, fail, requesturi set on client side", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		transport := setup(t, nil, true, handler)

		client := http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)
		req.RequestURI = "test"
		_, err = client.Do(req)
		require.Error(t, err)
	})

	t.Run("ohttp, fail, request body failed to close", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Empty(t, r.RemoteAddr)
		})

		transport := setup(t, nil, true, handler)

		client := http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid", strings.NewReader("hello world!"))
		require.NoError(t, err)

		req.Body = &closingReader{
			reader: req.Body,
			closeFunc: func() error {
				return assert.AnError
			},
		}

		_, err = client.Do(req)
		require.Error(t, err)
		require.ErrorIs(t, err, assert.AnError)
	})
}
