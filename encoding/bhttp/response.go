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
package bhttp

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/confidentsecurity/bhttp"
	"github.com/confidentsecurity/ohttp/encoding"
)

// ResponseEncoder encodes responses to bhttp.
type ResponseEncoder struct {
	cfg     config
	encoder *bhttp.ResponseEncoder
}

var _ encoding.ResponseEncoder = &ResponseEncoder{}

func newResponseEncoder(cfg config) *ResponseEncoder {
	encoder := cfg.customResponseEncoder
	if encoder == nil {
		encoder = &bhttp.ResponseEncoder{
			// bhttp considers the length prefix in the MaxChunkLen
			// so we don't need to account for it here.
			MaxEncodedChunkLen: cfg.responseChunkLen,
			MapFunc: func(hr *http.Response) (*bhttp.Response, error) {
				br, err := bhttp.MapFromHTTP1Response(hr)
				if err != nil {
					return nil, err
				}

				// match what net/http server does for responses.
				if !bodyAllowedForStatus(br.FinalStatusCode) {
					br.ContentLength = 0
					br.KnownLength = true
					br.FinalHeader.Del("Content-Length")
				}

				return br, nil
			},
		}
		if cfg.fixedResponseChunks {
			encoder.PadToMultipleOf = uint64(max(0, cfg.responseChunkLen)) // #nosec G115 -- i thought the linter clever
		}
	}

	return &ResponseEncoder{
		cfg:     cfg,
		encoder: encoder,
	}
}

// EncodeResponse encodes the provided http response to bhttp.
func (e *ResponseEncoder) EncodeResponse(_ context.Context, resp *http.Response) (*encoding.Message, error) {
	msg, err := e.encoder.EncodeResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to encode response to bhttp: %w", err)
	}

	var r io.Reader = msg
	mediaType := ResponseMediaType
	if msg.IsIndeterminateLength() {
		mediaType = ChunkedResponseMediaType
		if e.cfg.fixedResponseChunks {
			r = &exactChunkReader{
				chunkLen: e.cfg.responseChunkLen,
				r:        msg,
			}
		}
	}

	return &encoding.Message{
		Reader:    r,
		MediaType: []byte(mediaType),
		Chunked:   msg.IsIndeterminateLength(),
		ChunkLen:  e.cfg.responseChunkLen,
	}, nil
}

// ResponseDecoder decodes http respones from bhttp messages.
type ResponseDecoder struct {
	cfg     config
	decoder *bhttp.ResponseDecoder
}

var _ encoding.ResponseDecoder = &ResponseDecoder{}

func newResponseDecoder(cfg config) *ResponseDecoder {
	decoder := cfg.customResponseDecoder
	if decoder == nil {
		decoder = &bhttp.ResponseDecoder{}
	}

	return &ResponseDecoder{
		cfg:     cfg,
		decoder: decoder,
	}
}

// MaxChunkLen returns the maximum possible chunk length this decoder can decode.
func (d *ResponseDecoder) MaxChunkLen() int {
	return d.cfg.responseChunkLen
}

// MediaType returns the media type of messages this decoder can decode.
func (*ResponseDecoder) MediaType(chunked bool) []byte {
	if chunked {
		return ChunkedResponseMediaType.Bytes()
	}
	return ResponseMediaType.Bytes()
}

// DecodeResponse decodes the given bhttp message to a http response.
func (d *ResponseDecoder) DecodeResponse(ctx context.Context, r io.Reader, _ bool) (*http.Response, error) {
	resp, err := d.decoder.DecodeResponse(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response from bhttp: %w", err)
	}

	return resp, nil
}

func bodyAllowedForStatus(status int) bool {
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
