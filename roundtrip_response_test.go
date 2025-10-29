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
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidentsecurity/ohttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundtripResponse(t *testing.T) {
	const chunkingBufLen = 2048 // determined by net/http.

	tests := map[string]roundtripTest{
		"implicit 200 status code, nothing": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				// no write, no anything.
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, httpStatus(http.StatusOK), resp.Status)
				requireReadAll(t, resp.Body, "")
			},
		},
		"implicit 200 status code, write": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				n, err := w.Write([]byte("hello world!"))
				assert.NoError(t, err)
				assert.Equal(t, 12, n)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, httpStatus(http.StatusOK), resp.Status)
				requireReadAll(t, resp.Body, "hello world!")
			},
		},
		"explicit status code": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				require.Equal(t, httpStatus(http.StatusBadRequest), resp.Status)
				requireReadAll(t, resp.Body, "")
			},
		},
		"1xx status codes are remapped to 200": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusContinue)
				w.Write([]byte("hello world!"))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, httpStatus(http.StatusOK), resp.Status)
				require.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				requireReadAll(t, resp.Body, "hello world!")
			},
		},
		"body on 204 status code is ignored": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
				w.Write([]byte("hello world!"))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusNoContent, resp.StatusCode)
				require.Equal(t, httpStatus(http.StatusNoContent), resp.Status)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				requireReadAll(t, resp.Body, "")
			},
		},
		"body on 304 status code is ignored": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotModified)
				w.Write([]byte("hello world!"))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusNotModified, resp.StatusCode)
				require.Equal(t, httpStatus(http.StatusNotModified), resp.Status)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				requireReadAll(t, resp.Body, "")
			},
		},
		"implicit unchunked, no writes": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				// no write, no anything.
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"0"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(0), resp.ContentLength)
				require.Equal(t, []string(nil), resp.TransferEncoding)
				requireReadAll(t, resp.Body, "")
			},
		},
		"implicit unchunked, single write": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				n, err := w.Write([]byte("hello world!"))
				assert.NoError(t, err)
				assert.Equal(t, 12, n)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(12), resp.ContentLength)
				require.Equal(t, []string(nil), resp.TransferEncoding)
				requireReadAll(t, resp.Body, "hello world!")
			},
		},
		"implicit unchunked, single write max length": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				n, err := w.Write(bytes.Repeat([]byte("a"), chunkingBufLen))
				assert.NoError(t, err)
				assert.Equal(t, chunkingBufLen, n)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{strconv.Itoa(chunkingBufLen)},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(chunkingBufLen), resp.ContentLength)
				require.Equal(t, []string(nil), resp.TransferEncoding)
				requireReadAll(t, resp.Body, strings.Repeat("a", chunkingBufLen))
			},
		},
		"implicit unchunked, multiple writes max length": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				// worst case, write each byte individually.
				for _, b := range bytes.Repeat([]byte("a"), chunkingBufLen) {
					n, err := w.Write([]byte{b})
					assert.NoError(t, err)
					assert.Equal(t, 1, n)
				}
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{strconv.Itoa(chunkingBufLen)},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(chunkingBufLen), resp.ContentLength)
				require.Equal(t, []string(nil), resp.TransferEncoding)
				requireReadAll(t, resp.Body, strings.Repeat("a", chunkingBufLen))
			},
		},
		"explicit unchunked, zero length": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "0")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"0"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(0), resp.ContentLength)
				require.Equal(t, []string(nil), resp.TransferEncoding)
				requireReadAll(t, resp.Body, "")
			},
		},
		"explicit unchunked, single write over max implicit unchunked length": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "2049") // implicit buffer len + 1
				n, err := w.Write(bytes.Repeat([]byte("a"), 2049))
				assert.NoError(t, err)
				assert.Equal(t, 2049, n)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Length": []string{"2049"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(2049), resp.ContentLength)
				require.Equal(t, []string(nil), resp.TransferEncoding)
				requireReadAll(t, resp.Body, strings.Repeat("a", 2049))
			},
		},
		"explicit unchunked, multiple writes over max implicit unchunked length": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(chunkingBufLen+1))
				// worst case, write each byte individually.
				for _, b := range bytes.Repeat([]byte("a"), chunkingBufLen+1) {
					n, err := w.Write([]byte{b})
					assert.NoError(t, err)
					assert.Equal(t, 1, n)
				}
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, http.Header{
					"Content-Length": []string{strconv.Itoa(chunkingBufLen + 1)},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(2049), resp.ContentLength)
				require.Equal(t, []string(nil), resp.TransferEncoding)
				requireReadAll(t, resp.Body, strings.Repeat("a", chunkingBufLen+1))
			},
		},
		"implicit chunked, due to buffer length, single write": {
			outerResponseChunked: true,
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Write(bytes.Repeat([]byte("a"), 2049))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, http.Header{
					"Content-Type": []string{"text/plain; charset=utf-8"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, strings.Repeat("a", chunkingBufLen+1))
			},
		},
		"implicit chunked, due to buffer length, multiple writes": {
			outerResponseChunked: true,
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				// worst case, write each byte individually.
				for _, b := range bytes.Repeat([]byte("a"), chunkingBufLen+1) {
					n, err := w.Write([]byte{b})
					assert.NoError(t, err)
					assert.Equal(t, 1, n)
				}
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, http.Header{
					"Content-Type": []string{"text/plain; charset=utf-8"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, strings.Repeat("a", chunkingBufLen+1))
			},
		},
		"explicit chunked, due to single trailer": {
			outerResponseChunked: true,
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", "X-Custom-Trailer")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("hello world!"))
				w.Header().Set("X-Custom-Trailer", "abc")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Type": []string{"text/plain; charset=utf-8"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "hello world!")
				require.Equal(t, http.Header{
					"X-Custom-Trailer": []string{"abc"},
				}, resp.Trailer)
			},
		},
		"explicit chunked, due to multiple trailers via separate values": {
			outerResponseChunked: true,
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Trailer", "X-Custom-Trailer-1")
				w.Header().Add("Trailer", "X-Custom-Trailer-2")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("hello world!"))
				w.Header().Set("X-Custom-Trailer-1", "abc")
				w.Header().Set("X-Custom-Trailer-2", "def")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Type": []string{"text/plain; charset=utf-8"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "hello world!")
				require.Equal(t, http.Header{
					"X-Custom-Trailer-1": []string{"abc"},
					"X-Custom-Trailer-2": []string{"def"},
				}, resp.Trailer)
			},
		},
		"explicit chunked, due to multiple trailers in one value": {
			outerResponseChunked: true,
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", "X-Custom-Trailer-1, X-Custom-Trailer-2")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("hello world!"))
				w.Header().Set("X-Custom-Trailer-1", "abc")
				w.Header().Set("X-Custom-Trailer-2", "def")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Type": []string{"text/plain; charset=utf-8"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "hello world!")
				require.Equal(t, http.Header{
					"X-Custom-Trailer-1": []string{"abc"},
					"X-Custom-Trailer-2": []string{"def"},
				}, resp.Trailer)
			},
		},
		"explicit chunked, due to transfer-encoding header": {
			outerResponseChunked: true,
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Transfer-Encoding", "chunked")
				w.Write([]byte("hello world!"))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					// Transfer-Encoding header stripped away.
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "hello world!")
			},
		},
		"explicit chunked, due to transfer-encoding header, gzip is stripped": {
			outerResponseChunked: true,
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Transfer-Encoding", "chunked")
				w.Header().Add("Transfer-Encoding", "gzip")
				w.Write([]byte("hello world!"))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					// Transfer-Encoding header stripped away.
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "hello world!")
			},
		},
		"explicit chunked, but conflicting content length also provided": {
			outerResponseChunked: true,
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				// logs an error for the http test.
				w.Header().Set("Transfer-Encoding", "chunked")
				w.Header().Set("Content-Length", "12")
				w.Write([]byte("hello world!"))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "hello world!")
			},
		},
		"explicit chunked, due to flush, empty body": {
			outerResponseChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				flusher, ok := w.(http.Flusher)
				assert.True(t, ok)
				flusher.Flush()
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "")
			},
		},
		"explicit chunked, due to flush, single write before flush": {
			outerResponseChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("hello world!"))
				flusher, ok := w.(http.Flusher)
				assert.True(t, ok)
				flusher.Flush()
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Type": []string{"text/plain; charset=utf-8"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "hello world!")
			},
		},
		"explicit chunked, due to flush, single after flush": {
			outerResponseChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				flusher, ok := w.(http.Flusher)
				assert.True(t, ok)
				flusher.Flush()
				w.Write([]byte("hello world!"))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Date": []string{resp.Header.Get("Date")},
				}, resp.Header)

				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, "hello world!")
			},
		},
		"explicit chunked, due to flush, many writes and flushes": {
			outerResponseChunked: true,
			reqFunc: func(t *testing.T, serverURL string) *http.Request {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, serverURL, nil)
				require.NoError(t, err)
				return req
			},
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				flusher, ok := w.(http.Flusher)
				assert.True(t, ok)
				for _, b := range bytes.Repeat([]byte("a"), chunkingBufLen) {
					n, err := w.Write([]byte{b})
					assert.NoError(t, err)
					assert.Equal(t, 1, n)
					flusher.Flush()
				}
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, http.Header{
					"Content-Type": []string{"text/plain; charset=utf-8"},
					"Date":         []string{resp.Header.Get("Date")},
				}, resp.Header)
				require.Equal(t, int64(-1), resp.ContentLength)
				requireReadAll(t, resp.Body, strings.Repeat("a", chunkingBufLen))
			},
		},
		"header, nil date header removed date": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				h := w.Header()
				h.Add("Date", "")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Length": []string{"0"},
					"Date":           []string{""},
				}, resp.Header)
			},
		},
		"header, custom date header is forwarded": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Date", "abc")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Length": []string{"0"},
					"Date":           []string{"abc"},
				}, resp.Header)
			},
		},
		"header, forwards custom header without write": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Custom-Response", "abc")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Length":    []string{"0"},
					"Date":              []string{resp.Header.Get("Date")},
					"X-Custom-Response": []string{"abc"},
				}, resp.Header)
			},
		},
		"header, forwards custom header before write": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Custom-Response", "abc")
				w.Write([]byte("hello world!"))
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Length":    []string{"12"},
					"Content-Type":      []string{"text/plain; charset=utf-8"},
					"Date":              []string{resp.Header.Get("Date")},
					"X-Custom-Response": []string{"abc"},
				}, resp.Header)
			},
		},
		"header, ignores custom header after write": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("hello world!"))
				w.Header().Set("X-Custom-Response", "abc")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Length": []string{"12"},
					"Content-Type":   []string{"text/plain; charset=utf-8"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
			},
		},
		"header, forwards custom header before write header": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Custom-Response", "abc")
				w.WriteHeader(http.StatusOK)
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Length":    []string{"0"},
					"Date":              []string{resp.Header.Get("Date")},
					"X-Custom-Response": []string{"abc"},
				}, resp.Header)
			},
		},
		"header, ignores custom header after write header": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Header().Set("X-Custom-Response", "abc")
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, http.Header{
					"Content-Length": []string{"0"},
					"Date":           []string{resp.Header.Get("Date")},
				}, resp.Header)
			},
		},
		"proto fields are set": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Equal(t, "HTTP/1.1", resp.Proto)
				require.Equal(t, 1, resp.ProtoMajor)
				require.Equal(t, 1, resp.ProtoMinor)
			},
		},
		"uncompressed is false": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.False(t, resp.Uncompressed)
			},
		},
		"tls is nil": {
			handleFunc: func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			},
			verifyRespFunc: func(t *testing.T, resp *http.Response) {
				require.Nil(t, resp.TLS)
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
			require.NoError(t, err)
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

			transport := setup(t, nil, true, handler)

			client := http.Client{
				Timeout:   300 * time.Second,
				Transport: transport,
			}

			req := tc.newRequest(t, "http://ohttp.invalid")
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() {
				err = resp.Body.Close()
				require.NoError(t, err)
			}()

			tc.verifyResp(t, resp)
		})

		// This test verifies the shape of the outer response from the gateway.
		// The gateway will chunk this based on the encoder's decision to
		// chunk/not chunk the response.
		t.Run("ohttp, outer response, "+name, func(t *testing.T) {
			httpClient := http.Client{
				Transport: &verifyingTransport{
					orig: http.DefaultTransport,
					verifyResponse: func(resp *http.Response) {
						require.Equal(t, http.StatusOK, resp.StatusCode)
						if tc.outerResponseChunked {
							require.Equal(t, http.Header{
								"Content-Type": []string{"message/ohttp-chunked-res"},
								"Date":         []string{resp.Header.Get("Date")},
							}, resp.Header)
						} else {
							require.Equal(t, http.Header{
								"Content-Type":   []string{"message/ohttp-res"},
								"Content-Length": []string{resp.Header.Get("Content-length")},
								"Date":           []string{resp.Header.Get("Date")},
							}, resp.Header)
						}
						// ensure we can parse the date.
						_, err := time.Parse(http.TimeFormat, resp.Header.Get("Date"))
						assert.NoError(t, err)
					},
				},
			}

			opts := []ohttp.TransportOption{
				ohttp.WithHTTPClient(&httpClient),
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tc.handleFunc(t, w, r)
			})
			transport := setup(t, opts, true, handler)

			req := tc.newRequest(t, "http://ohttp.invalid")
			resp, err := transport.RoundTrip(req)
			require.NoError(t, err)
			defer func() {
				err = resp.Body.Close()
				require.NoError(t, err)
			}()
		})
	}

	t.Run("ohttp, chunked timing", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}

			for i := 0; i < 20; i++ {
				time.Sleep(50 * time.Millisecond)
				w.Write(bytes.Repeat([]byte("a"), 4096))
				flusher.Flush()
			}
		})

		transport := setup(t, nil, true, handler)

		client := http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()

		require.Equal(t, int64(-1), resp.ContentLength)

		assertChunkTiming(t, resp.Body, 4096)
	})

	t.Run("ohttp, chunked outer response", func(t *testing.T) {
		const (
			nrOfChunks              = 20
			maxBHTTPEncodedChunkLen = 4096
			userChunkLen            = maxBHTTPEncodedChunkLen - 2
			// OHTTP QUIC int length + AEAD overhead
			outChunkLen = maxBHTTPEncodedChunkLen + 2 + 16
		)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}

			for i := 0; i < nrOfChunks; i++ {
				w.Write(bytes.Repeat([]byte("a"), userChunkLen))
				flusher.Flush()
			}
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
							Conn:    conn,
							capRead: buf,
						}, nil
					},
				},
			},
		}

		opts := []ohttp.TransportOption{
			ohttp.WithHTTPClient(&httpClient),
		}

		transport := setup(t, opts, true, handler)

		req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid", nil)
		require.NoError(t, err)

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)

		_, err = io.ReadAll(resp.Body)
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

	t.Run("ohttp, chunked with multiple trailers", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}

			w.Header().Add("Trailer", "X-Test-1, X-Test-2")
			w.Header().Add("Trailer", "X-Test-2")
			for i := 0; i < 20; i++ {
				time.Sleep(50 * time.Millisecond)
				w.Write(bytes.Repeat([]byte("a"), 4096))
				flusher.Flush()
			}
			w.Header().Set("X-Test-1", "abc")
			w.Header().Set("X-Test-2", "def")
		})

		transport := setup(t, nil, true, handler)

		client := http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()

		require.Equal(t, int64(-1), resp.ContentLength)

		assertChunkTiming(t, resp.Body, 4096)

		require.Equal(t, http.Header{
			"X-Test-1": []string{"abc"},
			"X-Test-2": []string{"def"},
		}, resp.Trailer)
	})

	t.Run("ohttp, chunked close with partial read", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}

			for i := 0; i < 20; i++ {
				time.Sleep(50 * time.Millisecond)
				w.Write(bytes.Repeat([]byte("a"), 4096))
				flusher.Flush()
			}
		})

		transport := setup(t, nil, true, handler)

		client := http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid/", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()

		// only read up to half way then close.
		totalN := 0
		for i := 0; i < 20; i++ {
			buf := make([]byte, 4096)
			n, err := resp.Body.Read(buf)
			require.NoError(t, err)

			totalN += n
			if totalN > 10*4096 {
				break
			}
		}

		err = resp.Body.Close()
		require.NoError(t, err)
	})
}

func httpStatus(c int) string {
	return strconv.Itoa(c) + " " + http.StatusText(c)
}

type captureConn struct {
	net.Conn
	capWrite *bytes.Buffer
	capRead  *bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && c.capWrite != nil {
		c.capWrite.Write(p)
	}
	return n, err
}

func (c *captureConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.capRead != nil {
		c.capRead.Write(b[:n])
	}
	return n, err
}

func requireParseChunkLengths(t *testing.T, msg string) []int {
	t.Helper()

	// find start of body
	bodyStart := strings.Index(msg, "\r\n\r\n") + 4

	buf := bytes.NewBufferString(msg[bodyStart:])
	r := bufio.NewReader(buf)
	var out []int
	for {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}

		lenLine = strings.TrimSpace(lenLine)
		if lenLine == "" {
			continue
		}

		// Parse the hex size
		chunkLen, err := strconv.ParseInt(lenLine, 16, 64)
		require.NoError(t, err)
		out = append(out, int(chunkLen))

		// skip the data bytes
		skipBytes := chunkLen + 2 // +2 for \r\n
		for skipBytes > 0 {
			_, err := r.ReadByte()
			if err != nil {
				break
			}
			skipBytes--
		}
	}

	return out
}
