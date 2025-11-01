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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/ohttp/encoding"
	"github.com/confidentsecurity/ohttp/encoding/bhttp"
	"github.com/confidentsecurity/twoway"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// defaultUserAgent as added by the http.DefaultTransport when not explicitly overwritten.
// It can be overridden in the same way as with the default transport by setting the
// User-Agent header to nil or by providing a custom value.
const defaultUserAgent = "Go-http-client/1.1"

// Transport is a http.RoundTripper that transports
// requests and responses over OHTTP.
type Transport struct {
	relayURL   *url.URL
	sender     *twoway.RequestSender
	httpClient *http.Client
	encoder    encoding.RequestEncoder
	tracer     trace.Tracer
}

// NewTransport creates a new transport for the given keyConfig and options.
func NewTransport(keyConfig KeyConfig, relayURL string, opts ...TransportOption) (*Transport, error) {
	if err := keyConfig.valid(); err != nil {
		return nil, fmt.Errorf("invalid key config: %w", err)
	}
	suite := hpke.NewSuite(keyConfig.KemID, keyConfig.SymmetricAlgorithms[0].KDFID, keyConfig.SymmetricAlgorithms[0].AEADID)
	sender, err := twoway.NewRequestSender(suite, keyConfig.KeyID, keyConfig.PublicKey, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request sender: %w", err)
	}

	return NewTransportWithSender(sender, relayURL, opts...)
}

// NewTransportWithSender creates a new transport with the provided sender. This method
// allows for the creation of Transports with custom HPKE suites.
func NewTransportWithSender(sender *twoway.RequestSender, relayURL string, opts ...TransportOption) (*Transport, error) {
	rURL, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL: %w", err)
	}

	// set default config and overwrite them with options.
	defaultEnc, err := bhttp.NewRequestEncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create default request encoder: %w", err)
	}
	// default transport config
	cfg := &transportCfg{
		httpClient: http.DefaultClient,
		encoder:    defaultEnc,
		tracer:     noop.Tracer{},
	}

	for _, opt := range opts {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	return &Transport{
		relayURL:   rURL,
		sender:     sender,
		httpClient: cfg.httpClient,
		encoder:    cfg.encoder,
		tracer:     cfg.tracer,
	}, nil
}

// RoundTrip implements http.RoundTripper.
func (c *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	ctx, span := c.tracer.Start(req.Context(), "ohttp.Transport.RoundTrip")
	defer span.End()
	req = req.WithContext(ctx)

	defer func() {
		// Close request body as part of the roundtrip contract.
		// Only report close errors if no previous error occurred - the original
		// operation error is more important than a close error, which is often
		// a consequence of the original failure. This follows Go's standard
		// practice of prioritizing the most relevant error for the caller.
		if req.Body == nil {
			return
		}

		closeErr := req.Body.Close()
		if closeErr != nil && err == nil {
			err = fmt.Errorf("ohttp: failed to close request body: %w", closeErr)
		}

		// ensure we close the response body when an error happens.
		if err != nil && resp != nil && resp.Body != nil {
			resp.Body.Close()
			resp = nil
		}
	}()

	encapsulated, rd, err := c.Encapsulate(req)
	if err != nil {
		return nil, fmt.Errorf("ohttp: failed to encapsulate request: %w", err)
	}

	resp, err = c.httpClient.Do(encapsulated)
	if err != nil {
		return nil, fmt.Errorf("ohttp: failed to do request: %w", err)
	}

	resp, err = rd.Decapsulate(req.Context(), resp)
	if err != nil {
		return nil, fmt.Errorf("ohttp: failed to decapsulate response: %w", err)
	}

	return resp, nil
}

// Encapsulate encapsulates the request as an OHTTP request. Encapsulate returns the encapsulated request
// and a response decapsulator that can be used to decapsulate the corresponding response.
func (c *Transport) Encapsulate(req *http.Request) (*http.Request, *ResponseDecapsulator, error) {
	req, respDecap, _, err := c.EncapsulateWithMessageInfo(req)
	return req, respDecap, err
}

// EncapsulateWithMessageInfo does the same as Encapsulate, but returns additional meta data
// about the body of the encapsulated request.
//
//nolint:revive
func (c *Transport) EncapsulateWithMessageInfo(req *http.Request) (*http.Request, *ResponseDecapsulator, MessageInfo, error) {
	var info MessageInfo

	ctx, span := c.tracer.Start(req.Context(), "ohttp.Transport.Encapsulate")
	defer span.End()

	req = req.WithContext(ctx)
	req = c.adaptDefaultHTTPTransport(req)
	if req.Body != nil {
		req.Body = NewTracedReader(req.Context(), c.tracer, req.Body, "ohttp.RequestBodyReader")
	}
	reqMsg, respDecoder, err := c.encoder.EncodeRequest(req)
	if err != nil {
		return nil, nil, info, fmt.Errorf("failed to encode request: %w", err)
	}

	// encrypt the message chunked or unchunked.
	var sealOpts []twoway.Option
	if reqMsg.Chunked {
		sealOpts = append(sealOpts,
			twoway.EnableChunking(),
			twoway.WithMaxChunkPlaintextLen(reqMsg.ChunkLen),
		)
	}

	sealer, err := c.sender.NewRequestSealer(
		NewTracedReader(req.Context(), c.tracer, reqMsg, "ohttp.EncodedRequestReader"),
		reqMsg.MediaType,
		sealOpts...,
	)
	if err != nil {
		return nil, nil, info, fmt.Errorf("failed to create request sealer: %w", err)
	}

	// prepare the request to send to the relay and gateway.
	relayReq, err := http.NewRequestWithContext(
		req.Context(),
		http.MethodPost,
		c.relayURL.String(),
		NewTracedReader(req.Context(), c.tracer, sealer, "ohttp.SealedRequestReader"),
	)
	if err != nil {
		return nil, nil, info, fmt.Errorf("failed to create new relay request: %w", err)
	}

	// strip the default user agent.
	relayReq.Header["User-Agent"] = nil

	if sealedLen, ok := sealer.Len(); ok {
		relayReq.ContentLength = int64(sealedLen)
	}

	// add the date header.
	now := time.Now().UTC()
	relayReq.Header.Set("Date", now.Format(http.TimeFormat))

	// set appropriate headers.
	if reqMsg.Chunked {
		relayReq.Header.Set("Content-Type", ChunkedRequestMediaType)
		// Set Incremental header to ensure chunked content is delivered incrementally
		// instead of being buffered by intermediaries (like the relay).
		relayReq.Header.Set("Incremental", "?1")
	} else {
		relayReq.Header.Set("Content-Type", RequestMediaType)
	}

	info.HeaderLen = sealer.HeaderLen()
	info.Length, _ = sealer.Len()
	info.MaxCiphertextChunkLen, _ = sealer.MaxCiphertextChunkLen()

	return relayReq, &ResponseDecapsulator{
		sealer:  sealer,
		decoder: respDecoder,
		tracer:  c.tracer,
	}, info, nil
}

// adaptDefaultHTTPTransport clones the request and modifies the cloned request
// to include the exact fields that are normally added by the http.DefaultTransport.
func (*Transport) adaptDefaultHTTPTransport(req *http.Request) *http.Request {
	clone := req.Clone(req.Context())

	if clone.Method == "" {
		clone.Method = http.MethodGet
	}

	val, ok := clone.Header["User-Agent"]
	if !ok {
		clone.Header.Set("User-Agent", defaultUserAgent)
	} else if ok && val == nil {
		clone.Header.Del("User-Agent")
	}

	// just like net/http we strip the transfer-encoding header.
	// only the .TransferEncoding field is relevant.
	clone.Header.Del("Transfer-Encoding")

	// Go only allows for chunked transfer encoding for requests.
	if len(clone.TransferEncoding) > 0 {
		if clone.TransferEncoding[0] != "chunked" {
			clone.TransferEncoding = nil
		} else {
			clone.TransferEncoding = []string{"chunked"}
			clone.ContentLength = -1
		}
	}

	// add content length header for unchunked requests.
	if clone.ContentLength > 0 && len(clone.TransferEncoding) == 0 {
		clone.Header.Set("Content-Length", strconv.Itoa(int(clone.ContentLength)))
	}

	return clone
}

type readerClosers struct {
	reader  io.Reader
	closers []io.Closer
}

func (rc *readerClosers) Read(p []byte) (int, error) {
	return rc.reader.Read(p)
}

func (rc *readerClosers) Close() error {
	var err error
	for _, c := range rc.closers {
		err = errors.Join(err, c.Close())
	}
	return err
}

// ResponseDecapsulator decapsulates an OHTTP response.
type ResponseDecapsulator struct {
	sealer  *twoway.RequestSealer
	decoder encoding.ResponseDecoder
	tracer  trace.Tracer
}

// Decapsulate decapsulates the provided OHTTP response and returns the original response.
func (d *ResponseDecapsulator) Decapsulate(ctx context.Context, encapResp *http.Response) (*http.Response, error) {
	ctx, span := d.tracer.Start(ctx, "ohttp.Transport.Decapsulate")
	defer span.End()

	if encapResp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected status code, wanted %d got %d", http.StatusOK, encapResp.StatusCode)
		return nil, ResponseStatusError{
			StatusCode: encapResp.StatusCode,
			Err:        err,
		}
	}

	encapResp.Body = NewTracedReader(ctx, d.tracer, encapResp.Body, "ohttp.SealedResponseReader")

	var openOpts []twoway.Option
	chunkedResp := false
	respContentType := encapResp.Header.Get("Content-Type")
	switch respContentType {
	case ResponseMediaType:
		// nothing to do, but valid value.
	case ChunkedResponseMediaType:
		chunkedResp = true
		openOpts = append(openOpts,
			twoway.EnableChunking(),
			twoway.WithMaxChunkPlaintextLen(d.decoder.MaxChunkLen()),
		)
	default:
		return nil, fmt.Errorf("invalid response Content-Type from relay: %v", respContentType)
	}

	opener, err := d.sealer.NewResponseOpener(encapResp.Body, d.decoder.MediaType(chunkedResp), openOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create response opener: %w", err)
	}

	resp, err := d.decoder.DecodeResponse(ctx, opener, chunkedResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.Body != nil {
		resp.Body = NewTracedReader(ctx, d.tracer, resp.Body, "ohttp.ResponseBodyReader")
	}

	// make sure that closing the body on the new resp also closes the body on the relay response.
	resp.Body = &readerClosers{
		reader: resp.Body,
		closers: []io.Closer{
			resp.Body,
			encapResp.Body,
		},
	}

	return resp, nil
}
