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

// RequestEncoder encodes requests to bhttp.
type RequestEncoder struct {
	cfg         config
	encoder     *bhttp.RequestEncoder
	respDecoder encoding.ResponseDecoder
}

var _ encoding.RequestEncoder = &RequestEncoder{}

// NewRequestEncoder creates a new request encoder.
func NewRequestEncoder(opts ...Option) (*RequestEncoder, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	encoder := cfg.customRequestEncoder
	if encoder == nil {
		encoder = &bhttp.RequestEncoder{
			MaxEncodedChunkLen: cfg.requestChunkLen,
		}
		if cfg.fixedRequestChunks {
			encoder.PadToMultipleOf = uint64(max(0, cfg.requestChunkLen)) // #nosec G115 -- i thought the linter clever
		}
	}

	return &RequestEncoder{
		cfg:         cfg,
		encoder:     encoder,
		respDecoder: newResponseDecoder(cfg),
	}, nil
}

// EncodeRequest encodes a request to a bhttp message, the returned response decoder can
// be used to decode the expected response for this request.
func (e *RequestEncoder) EncodeRequest(req *http.Request) (*encoding.Message, encoding.ResponseDecoder, error) {
	msg, err := e.encoder.EncodeRequest(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to bhttp encode request: %w", err)
	}

	var r io.Reader = msg
	mt := RequestMediaType
	if msg.IsIndeterminateLength() {
		mt = ChunkedRequestMediaType
		if e.cfg.fixedRequestChunks {
			r = &exactChunkReader{
				chunkLen: e.cfg.requestChunkLen,
				r:        msg,
			}
		}
	}

	return &encoding.Message{
		Reader:    r,
		MediaType: mt.Bytes(),
		Chunked:   msg.IsIndeterminateLength(),
		ChunkLen:  e.cfg.requestChunkLen,
	}, e.respDecoder, nil
}

// RequestDecoder decodes a bhttp message to a request.
type RequestDecoder struct {
	cfg         config
	respEncoder encoding.ResponseEncoder
	decoder     *bhttp.RequestDecoder
}

var _ encoding.RequestDecoder = &RequestDecoder{}

// NewRequestDecoder creates a new request decoder.
func NewRequestDecoder(opts ...Option) (*RequestDecoder, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	decoder := cfg.customRequestDecoder
	if decoder == nil {
		decoder = &bhttp.RequestDecoder{}
	}

	return &RequestDecoder{
		cfg:         cfg,
		decoder:     decoder,
		respEncoder: newResponseEncoder(cfg),
	}, nil
}

// MaxChunkLen returns the maximum chunk length for this request decoder.
func (d *RequestDecoder) MaxChunkLen() int {
	return d.cfg.requestChunkLen
}

// MediaType returns the media type for this request decoder.
func (*RequestDecoder) MediaType(chunked bool) []byte {
	if chunked {
		return ChunkedRequestMediaType.Bytes()
	}
	return RequestMediaType.Bytes()
}

// DecodeRequest decodes a bhttp message to a HTTP request.
func (d *RequestDecoder) DecodeRequest(ctx context.Context, r io.Reader, _ bool) (*http.Request, encoding.ResponseEncoder, error) {
	req, err := d.decoder.DecodeRequest(ctx, r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode request from bhttp: %w", err)
	}

	return req, d.respEncoder, nil
}

// exactChunkReader reads chunks of an exact size. Expects the underlying reader
// to always return multiples of the chunk length.
type exactChunkReader struct {
	chunkLen int
	r        io.Reader
	eof      bool
}

func (r *exactChunkReader) Read(p []byte) (int, error) {
	if r.eof {
		return 0, io.EOF
	}

	if len(p) != r.chunkLen {
		return 0, fmt.Errorf("expected p to have len %d but got %d", r.chunkLen, len(p))
	}

	n, err := io.ReadFull(r.r, p)
	if n == 0 {
		r.eof = true
	}
	return n, err
}
