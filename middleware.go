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
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"maps"
)

var ErrChunkedResponseEncoderMismatch = errors.New("ohttp.Middleware used with an incompatible response encoder")

// Middleware uses the gateway as a handler middleware.
//
// The wrapped handler represents a Target Resource. It receives the
// decapsulated request and writes a decapsulated response. It can either deal with these directly,
// or proxy them elsewhere.
//
// The Middleware follows the net/http Server logic when deciding whether a response should be
// chunked or not. Upon detecting a chunked response, it will encapsulate and begin streaming chunks.
//
// Important when using custom response encoders: This middleware is only compatible with response encoders
// that map responses with chunked Transfer-Encoding, to chunked OHTTP messages. If there is disagreement,
// this handler will begin returning [ErrChunkedResponseEncoderMismatch]. It will also call the error handler
// on the gateway with this error.
//
// The default BHTTP encoding is fully compatible with this middleware.
func Middleware(g *Gateway, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := g.tracer.Start(r.Context(), "ohttp.Middleware")
		defer span.End()
		r = r.WithContext(ctx)

		req, respEncapper, err := g.Decapsulate(r)
		if err != nil {
			g.cfg.errorHandler.HandleError(w, false, err)
			return
		}

		slog.InfoContext(r.Context(), "Gateway Forwarding Request", "host", req.Host, "url", req.URL.String())

		rw := &responseWriter{
			orig:         w,
			recorder:     newResponseRecorder(),
			encapsulator: respEncapper,
		}

		innerCtx, innerSpan := g.tracer.Start(r.Context(), "ohttp.Middleware.inner")
		next.ServeHTTP(rw, req.WithContext(innerCtx))
		innerSpan.End()

		// important: close the responseWriter so we will wait for async chunked response
		// processing to complete.
		err = rw.Close()
		if err != nil {
			// headers will have been written by this point, so we pass true.
			g.cfg.errorHandler.HandleError(w, true, err)
			return
		}
	})
}

// responseWriter captures writes in the recorder until it knows for certain whether
// the response is a unchunked or chunked response, after which it instantiates the
// correct writer.
type responseWriter struct {
	// orig is the real response writer to which the recorded response should be written.
	orig         http.ResponseWriter
	recorder     *responseRecorder
	encapsulator *ResponseEncapsulator

	// asyncBodyWriter is set when we're writing a chunked response.
	asyncBodyWriter *chunkedBody

	// asyncBeginErr indicates we attempted to begin async encapsulation
	// but failed. It's not an actual field that's written to in an async manner.
	//
	// when this field is set it means that the response writer is an error state.
	asyncBeginErr error
}

func (c *responseWriter) Header() http.Header {
	return c.recorder.Header()
}
func (c *responseWriter) WriteHeader(code int) {
	if c.asyncBeginErr != nil {
		return
	}

	c.recorder.WriteHeader(code)
}

func (c *responseWriter) Write(p []byte) (int, error) {
	if c.asyncBeginErr != nil {
		return 0, c.asyncBeginErr
	}

	if !c.recorder.bodyAllowedForStatus() {
		// pretend to write the body for responses that don't allow one.
		return len(p), nil
	}

	if c.asyncBodyWriter != nil {
		// We've began writing a chunked response. Write to the chunked reader instead.
		return c.asyncBodyWriter.Write(p)
	}

	// we're not chunking (but might in the future), write to the recorder.
	n, err := c.recorder.Write(p)
	if err != nil {
		return n, err
	}

	// this write could have made the response a chunked response.
	if c.recorder.wouldTransferChunkedInStdLib() {
		c.asyncBodyWriter, c.asyncBeginErr = c.beginEncapsulationAsync()
	}

	return n, err
}

func (c *responseWriter) Flush() {
	if c.asyncBodyWriter != nil || c.asyncBeginErr != nil {
		// we're already chunking or encountered an irrecoverable error, nothing to do.
		return
	}

	// first flush should always result in a chunked response.
	c.asyncBodyWriter, c.asyncBeginErr = c.beginEncapsulationAsync()
}

func (c *responseWriter) Close() error {
	if c.asyncBeginErr != nil {
		// if this error is set it means that the asyncBodyWriter goroutine never began,
		// so it's safe to exit here.
		return c.asyncBeginErr
	}

	if c.asyncBodyWriter != nil {
		// waits for the async writing to complete.
		return c.asyncBodyWriter.Close()
	}

	// didn't ever begin writing an async chunked response. So write
	// the recorded response synchronously.
	resp := c.recorder.finish()
	encapResp, err := c.encapsulator.Encapsulate(resp)
	if err != nil {
		return fmt.Errorf("failed to encapsulate response: %w", err)
	}

	return writeEncapsulatedRespSync(c.orig, encapResp)
}

func writeEncapsulatedRespSync(rw http.ResponseWriter, resp *http.Response) error {
	// write the header
	writeEncapRespHeader(rw, resp)

	// write the body
	_, err := io.Copy(rw, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write response body: %w", err)
	}

	// close the body.
	err = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to close body: %w", err)
	}
	return nil
}

func (c *responseWriter) beginEncapsulationAsync() (*chunkedBody, error) {
	pReader, pWriter := io.Pipe()

	resp := c.recorder.finishChunked(pReader)
	encapResp, msgInfo, err := c.encapsulator.EncapsulateWithMessageInfo(resp)
	if err != nil {
		return nil, err
	}

	if !isChunkedTransferEncoding(encapResp.TransferEncoding) {
		return nil, ErrChunkedResponseEncoderMismatch
	}

	done := make(chan error)
	go func() {
		// write the header.
		writeEncapRespHeader(c.orig, encapResp)

		// write the body until pReader is closed.
		err := writeChunkedBody(c.orig, encapResp.Body, msgInfo)
		if err != nil {
			// drain the rest of encapsulated response body to make sure
			// we don't block the pWriter.
			_, discardErr := io.Copy(io.Discard, encapResp.Body)
			err = errors.Join(err, discardErr)
		}
		// at this point we know for sure that pWriter has been closed as
		// pReader has returned io.EOF.

		// close the body on the response.
		err = errors.Join(err, encapResp.Body.Close())

		done <- err
	}()

	// note for future: be careful not to return an error here without waiting
	// for the goroutine to finish.

	return &chunkedBody{
		pWriter: pWriter,
		done:    done,
	}, nil
}

type chunkedBody struct {
	pWriter *io.PipeWriter
	done    chan error
}

func (w *chunkedBody) Write(p []byte) (int, error) {
	return w.pWriter.Write(p)
}

func (w *chunkedBody) Close() error {
	w.pWriter.Close()

	// wait for the body writing routine to finish.
	return <-w.done
}

func writeEncapRespHeader(rw http.ResponseWriter, resp *http.Response) {
	maps.Copy(rw.Header(), resp.Header)
	if isChunkedTransferEncoding(resp.TransferEncoding) {
		rw.Header().Set("Transfer-Encoding", "chunked")
	}
	rw.WriteHeader(resp.StatusCode)
}

func writeChunkedBody(rw http.ResponseWriter, r io.Reader, msgInfo MessageInfo) error {
	// write the header.
	headerBuf := make([]byte, msgInfo.HeaderLen)
	headerReader := io.LimitReader(r, int64(msgInfo.HeaderLen))
	_, err := io.CopyBuffer(rw, headerReader, headerBuf)
	if err != nil {
		return fmt.Errorf("failed to copy sealer header: %w", err)
	}

	// write the chunks.
	flusher, isFlusher := rw.(http.Flusher)
	buf := make([]byte, max(1, msgInfo.MaxCiphertextChunkLen))
	// adapted from io.CopyBuffer and inserted a flush after the write.
	for {
		nr, err := r.Read(buf)
		if nr > 0 {
			// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
			nw, errW := rw.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				return errors.New("invalid write")
			}
			if errW != nil {
				return errW
			}
			if nr != nw {
				return io.ErrShortWrite
			}

			// flush after each write when we're writing chunks.
			if isFlusher {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// responseRecorder captures a response.
type responseRecorder struct {
	header http.Header // active header so we can track trailers being added.
	body   *bytes.Buffer
	resp   *http.Response
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{
		header: http.Header{},
		body:   &bytes.Buffer{},
		resp: &http.Response{
			Status:        "",
			StatusCode:    0,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        nil,
			Body:          http.NoBody, // will be handled separately.
			ContentLength: 0,           // assume we'll start with a known length response.
			Trailer:       nil,
		},
	}
}

func (w *responseRecorder) wouldTransferChunkedInStdLib() bool {
	// Content-Length was set, stdlib never chunks.
	if w.resp.Header.Get("Content-Length") != "" {
		return false
	}

	// Transfer-Encoding was set to chunked, stdlib would chunk.
	if w.resp.Header.Get("Transfer-Encoding") == "chunked" {
		return true
	}

	// No Content-Length, but the recorded body was beyond the
	// default buffer size. Stdlib begins chunking.
	if w.body.Len() > 2048 {
		return true
	}

	// Trailer header was set. Stdlib chunks.
	if w.resp.Header.Get("Trailer") != "" {
		return true
	}

	return false
}

func (w *responseRecorder) Header() http.Header {
	return w.header
}

func (w *responseRecorder) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	n, err := w.body.Write(p)
	if err != nil {
		return 0, err
	}

	return n, err
}

func (w *responseRecorder) WriteHeader(c int) {
	if w.resp.StatusCode != 0 {
		// already wrote header.
		return
	}

	// remap 1xx status codes to http.StatusOK
	if c >= 100 && c <= 199 {
		c = http.StatusOK
	}

	w.resp.Status = http.StatusText(c)
	w.resp.StatusCode = c
	w.resp.Header = w.header.Clone()
}

// finish stops recording and returns the response.
func (w *responseRecorder) finish() *http.Response {
	w.WriteHeader(http.StatusOK)

	if w.bodyAllowedForStatus() {
		// set content length header and field.
		if contentLen, ok := w.knownContentLength(); ok {
			w.resp.Header.Set("Content-Length", strconv.FormatInt(contentLen, 10))
			w.resp.ContentLength = contentLen
		} else {
			w.resp.Header.Del("Content-Length")
			w.resp.ContentLength = -1
		}
	}

	// automatically snif content-type when possible.
	if contentType, ok := w.sniffContentType(); ok {
		w.resp.Header.Set("Content-Type", contentType)
	}

	// set Date header unless user explicitly set it to nil.
	if _, ok := w.resp.Header["Date"]; !ok {
		w.resp.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}

	// Move Trailer Header to response Trailer.
	if w.resp.Header.Get("Trailer") != "" {
		w.resp.Trailer = w.trailerFromHeaderVals(w.resp.Header.Values("Trailer"))
		w.resp.Header.Del("Trailer")
	}

	// always remove the transfer encoding.
	w.resp.Header.Del("Transfer-Encoding")

	// default to setting the trailers when reading from the buffer is complete.
	w.resp.Body = trailerReader(w.body, w.header, w.resp.Trailer)

	return w.resp
}

func (w *responseRecorder) finishChunked(pReader *io.PipeReader) *http.Response {
	resp := w.finish()

	// overwrite the body and hook in the chunk reader.
	w.resp.Body = &readerClosers{
		reader: trailerReader(io.MultiReader(
			w.body,
			pReader,
		), w.header, w.resp.Trailer),
		closers: []io.Closer{
			pReader,
		},
	}
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	resp.TransferEncoding = []string{"chunked"}
	return resp
}

func trailerReader(r io.Reader, srcHeader, dstHeader http.Header) io.ReadCloser {
	return &eofCallbackReader{
		reader: r,
		callback: func() {
			// copy trailers from headers when EOF is reached on the body.
			for trailer := range dstHeader {
				dstHeader[trailer] = srcHeader.Values(trailer)
			}
		},
	}
}

func (w *responseRecorder) bodyAllowedForStatus() bool {
	status := w.resp.StatusCode
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	default:
	}
	return true
}

func (w *responseRecorder) knownContentLength() (int64, bool) {
	// Order of the checks below is important to match behaviour of net/http.

	// if there is an explicit Transfer-Encoding,
	if w.resp.Header.Get("Transfer-Encoding") == "chunked" {
		return 0, false
	}

	// response with a trailer never have a known content length.
	if w.resp.Header.Get("Trailer") != "" {
		return 0, false
	}

	// explicit content-length, use it if a valid string.
	if w.resp.Header.Get("Content-Length") != "" {
		contentLen, err := strconv.ParseInt(w.resp.Header.Get("Content-Length"), 10, 64)
		if err == nil {
			return contentLen, true
		}
	}

	// fall back to using the buffer length (like the http.Server).
	return int64(w.body.Len()), true
}

func (w *responseRecorder) sniffContentType() (string, bool) {
	// don't sniff when a content-type has been provided.
	if _, ok := w.resp.Header["Content-Type"]; ok {
		return "", false
	}

	if w.body.Len() == 0 {
		// net/http server does not add a sniffed content type when
		// Content-Length is zero.
		return "", false
	}

	// net/http server does not sniff content types when transfer-encoding is
	// explicitly set to chunked.
	if w.resp.Header.Get("Transfer-Encoding") == "chunked" {
		return "", false
	}

	return http.DetectContentType(w.body.Bytes()), true
}

func (*responseRecorder) trailerFromHeaderVals(vals []string) http.Header {
	if len(vals) == 0 {
		return nil
	}

	trailer := make(http.Header)
	for _, val := range vals {
		for name := range strings.SplitSeq(val, ",") {
			name = strings.TrimSpace(name)
			trailer[name] = nil
		}
	}

	return trailer
}

type eofCallbackReader struct {
	reader   io.Reader
	callback func()
}

func (r *eofCallbackReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if errors.Is(err, io.EOF) {
		r.callback()
	}
	return n, err
}

func (*eofCallbackReader) Close() error {
	// noop.
	return nil
}
