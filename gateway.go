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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/confidentsecurity/ohttp/encoding"
	"github.com/confidentsecurity/twoway"
	"go.opentelemetry.io/otel/trace"
)

// ErrorHandler is used to write or log errors from the Gateway.
type ErrorHandler interface {
	// HandleError handles the provided error.
	//
	// headersWritten indicates whether the error handler can still write headers or not.
	//
	// Because the Gateway records the response of the inner handler, there is no guarantee
	// that the inner handler writing a header will also make the Gateway immediately write a header.
	HandleError(w http.ResponseWriter, headersWritten bool, err error)
}

// RequestValidator validates decapsulated requests before the Gateway forwards them
// the wrapped handler.
//
// The validator operates on the same request as the wrapped handler. Keep that in mind
// if the request body is read as part of validation.
//
// When using creating a custom request validator for a Gateway that redirects decapsulated
// requests be sure to validate the hostname to prevent unexpected redirects.
type RequestValidator interface {
	ValidRequest(r *http.Request) error
}

// Gateway is an OHTTP Gateway. It decapsulates incoming requests and encapsulates outgoing responses.
//
// The Gateway is designed to be used as a http Middleware but can also be used as a standalone component
// by calling [DecapRequest] directly.
//
// By default the Gateway only accepts decapsulated requests with a [DefaultAllowedHostname] hostname. This is to
// prevent the Gateway being used as a relay to arbitrary Target Resources.
//
// This behaviour can be overwritten by providing a custom [HostnameAllowlist] or [RequestValidator] implementation.
type Gateway struct {
	randReader io.Reader
	finder     SecretKeyFinder
	cfg        *gatewayCfg
	tracer     trace.Tracer
}

// NewGateway creates a new OHTTP Gateway.
func NewGateway(finder SecretKeyFinder, opts ...GatewayOption) (*Gateway, error) {
	cfg, err := defaultGatewayConfig()
	if err != nil {
		return nil, err
	}

	for _, opt := range opts {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	return &Gateway{
		finder: finder,
		cfg:    cfg,
		tracer: cfg.tracer,
	}, nil
}

// Decapsulate decapsulates an OHTTP request. Decapsulate returns the decapsulated request
// as well as a response encapsulator that can be used to encapsulate the corresponding response.
func (g *Gateway) Decapsulate(r *http.Request) (*http.Request, *ResponseEncapsulator, error) {
	ctx, span := g.tracer.Start(r.Context(), "ohttp.Gateway.Decapsulate")
	defer span.End()
	r = r.WithContext(ctx)

	// preparse the request header so we can find the appropriate key.
	header, err := parseRequestHeader(r)
	if err != nil {
		return nil, nil, err
	}

	// find the appropriate private key for the header
	secretKeyInfo, err := g.finder.FindSecretKey(r.Context(), header)
	if err != nil {
		var code ErrorCode
		switch {
		case errors.Is(err, errorKeyNotFound):
			code = ErrorCodeKeyNotFound
		case errors.Is(err, ErrorKeyNotYetActive), errors.Is(err, ErrorKeyExpired):
			code = ErrorCodeInactiveKey
		default:
			code = ErrorCodeKeyNotFound
		}

		return nil, nil, GatewayError{
			Code: code,
			Err:  err,
		}
	}

	decapReq, respEncapper, err := g.decapRequest(r, secretKeyInfo)
	if err != nil {
		// decapRequest already returns GatewayErrors where appropriate.
		return nil, nil, err
	}

	if g.cfg.reqValidator != nil {
		err = g.cfg.reqValidator.ValidRequest(decapReq)
		if err != nil {
			return nil, nil, GatewayError{
				Code: ErrorCodeInvalidRequest,
				Err:  err,
			}
		}
	}

	return decapReq, respEncapper, nil
}

// ResponseEncapsulator encapsulates a response.
type ResponseEncapsulator struct {
	ctx         context.Context
	reqOpener   *twoway.RequestOpener
	respEncoder encoding.ResponseEncoder
}

// Encapsulate encapsulates the response as an OHTTP response.
func (e *ResponseEncapsulator) Encapsulate(resp *http.Response) (*http.Response, error) {
	resp, _, err := e.EncapsulateWithMessageInfo(resp)
	return resp, err
}

// EncapsulateWithMessageInfo does the same [Encapsulate] but returns additional meta
// data about the body of the encapsulated response.
func (e *ResponseEncapsulator) EncapsulateWithMessageInfo(resp *http.Response) (*http.Response, MessageInfo, error) {
	var info MessageInfo
	msg, err := e.respEncoder.EncodeResponse(e.ctx, resp)
	if err != nil {
		return nil, info, GatewayError{
			Code: ErrorCodeResponseEncoding,
		}
	}

	var sealerOpts []twoway.Option
	if msg.Chunked {
		sealerOpts = append(
			sealerOpts,
			twoway.EnableChunking(),
			twoway.WithMaxChunkPlaintextLen(msg.ChunkLen),
		)
	}
	sealer, err := e.reqOpener.NewResponseSealer(msg.Reader, msg.MediaType, sealerOpts...)
	if err != nil {
		return nil, info, GatewayError{
			Code: ErrorCodeResponseEncryption,
			Err:  fmt.Errorf("failed to create response sealer: %w", err),
		}
	}

	encapResp := &http.Response{
		Status:     http.StatusText(http.StatusOK),
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body: &readerClosers{
			reader: sealer,
			closers: []io.Closer{
				resp.Body,
			},
		},
		Header: make(http.Header),
	}

	if contentLen, ok := sealer.Len(); ok {
		// unchunked
		encapResp.Header.Set("Content-Type", ResponseMediaType)
		encapResp.Header.Set("Content-Length", strconv.Itoa(contentLen))
		encapResp.ContentLength = int64(contentLen)
	} else {
		// chunked
		encapResp.Header.Set("Content-Type", ChunkedResponseMediaType)
		encapResp.TransferEncoding = []string{"chunked"}
		encapResp.ContentLength = -1
	}

	info.HeaderLen = sealer.HeaderLen()
	info.Length, _ = sealer.Len()
	info.MaxCiphertextChunkLen, _ = sealer.MaxCiphertextChunkLen()

	return encapResp, info, nil
}

//nolint:revive
func (g *Gateway) decapRequest(r *http.Request, ski SecretKeyInfo) (*http.Request, *ResponseEncapsulator, error) {
	reqContentType := r.Header.Get("Content-Type")
	chunkedReq := false
	var openOpts []twoway.Option
	switch reqContentType {
	case RequestMediaType:
		// nothing to do, but valid value.
	case ChunkedRequestMediaType:
		chunkedReq = true
		openOpts = append(openOpts,
			twoway.EnableChunking(),
			twoway.WithMaxChunkPlaintextLen(g.cfg.decoder.MaxChunkLen()),
		)
	default:
		return nil, nil, GatewayError{
			Code: ErrorCodeInvalidRequestContentType,
			Err:  errors.New("unknown content type"),
		}
	}

	receiver, err := twoway.NewRequestReceiverWithCustomSuite(ski.Suite, ski.KeyID, ski.Key, g.randReader)
	if err != nil {
		return nil, nil, GatewayError{
			Code: ErrorCodeInvalidKey,
			Err:  fmt.Errorf("failed to create request receiver: %w", err),
		}
	}

	opener, err := receiver.NewRequestOpener(r.Body, g.cfg.decoder.MediaType(chunkedReq), openOpts...)
	if err != nil {
		return nil, nil, GatewayError{
			Code: ErrorCodeInvalidKey,
			Err:  fmt.Errorf("failed to create request opener: %w", err),
		}
	}

	ctx := r.Context()
	ptReq, respEncoder, err := g.cfg.decoder.DecodeRequest(ctx, opener, chunkedReq)
	if err != nil {
		return nil, nil, GatewayError{
			Code: ErrorCodeRequestDecoding,
			Err:  fmt.Errorf("failed to decode request: %w", err),
		}
	}

	if ptReq.ContentLength == -1 {
		// Pretend this was send using chunked transfer-encoding.
		//
		// TODO: Currently the ohttp package operates on the assumption that
		// all unknown-length messages will always use Transfer-Encoding: chunked.
		//
		// While its very common for unknown-length HTTP messages to use
		// Transfer-Encoding: chunked, this is not a requirement. We should update
		// our code to reflect this.
		ptReq.TransferEncoding = []string{"chunked"}
	}

	return ptReq, &ResponseEncapsulator{
		reqOpener:   opener,
		respEncoder: respEncoder,
	}, nil
}

func parseRequestHeader(r *http.Request) (twoway.RequestHeader, error) {
	// parse the request header from the first 7 bytes of the request body.
	headerB := make([]byte, twoway.BinaryRequestHeaderLen)
	_, err := io.ReadFull(r.Body, headerB)
	if err != nil {
		return twoway.RequestHeader{}, GatewayError{
			Code: ErrorCodeRequestIO,
			Err:  fmt.Errorf("failed to read header bytes: %w", err),
		}
	}

	header, err := twoway.ParseRequestHeaderFrom(headerB)
	if err != nil {
		return twoway.RequestHeader{}, GatewayError{
			Code: ErrorCodeInvalidRequestHeader,
			Err:  err,
		}
	}

	// add the bytes back to the request body, twoway expects them to be there.
	r.Body = &readerClosers{
		reader:  io.MultiReader(bytes.NewReader(headerB), r.Body),
		closers: []io.Closer{r.Body},
	}

	return header, nil
}

// MessageInfo returns additional information about an OHTTP message.
type MessageInfo struct {
	// Len indicates the length of an unchunked OHTTP message.
	Length int
	// HeaderLen returns the length of the fixed header portion of this message.
	HeaderLen int
	// MaxCiphertextChunkLen returns the maximum length of a ciphertext chunk. Only applies
	// to chunked OHTTP messages.
	MaxCiphertextChunkLen int
}
