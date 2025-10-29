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
	"fmt"

	"github.com/confidentsecurity/bhttp"
)

const (
	// rfcMaxChunkLen specifies the maximum chunk length that senders are allowed to send
	// and receivers should be able to receive. This chunk length is prior to encapsulation.
	//
	// See this section of the RFC:
	//
	// https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html#name-chunked-requests-and-respon
	rfcMaxChunkLen = 16384

	// defaultSendChunkLen is a default chunk length we picked as the authors of this package,
	// it attempts to strike a balance between latency and throughput. This chunk length is prior to encapsulation.
	//
	// Depending on your use-case you might want a chunk length (lower latency), or a higher
	// chunk length (higher throughput).
	defaultSendChunkLen = 4096
)

// Option provides optional configuration for encoders/decoders.
type Option func(enc *config) error

type config struct {
	requestChunkLen       int
	fixedRequestChunks    bool
	responseChunkLen      int
	fixedResponseChunks   bool
	customRequestEncoder  *bhttp.RequestEncoder
	customRequestDecoder  *bhttp.RequestDecoder
	customResponseEncoder *bhttp.ResponseEncoder
	customResponseDecoder *bhttp.ResponseDecoder
}

func defaultConfig() config {
	return config{
		requestChunkLen:  defaultSendChunkLen,
		responseChunkLen: rfcMaxChunkLen,
	}
}

// MaxRequestChunkLen sets the maximum request chunk length.
func MaxRequestChunkLen(chunkLen int) Option {
	return func(enc *config) error {
		if chunkLen < 0 {
			return fmt.Errorf("chunk length should be positive, got %d", chunkLen)
		}
		if chunkLen > rfcMaxChunkLen {
			return fmt.Errorf("chunk would exceed maximum length per RFC 9458: %d > %d", chunkLen, rfcMaxChunkLen)
		}
		enc.requestChunkLen = chunkLen
		return nil
	}
}

// FixedLengthRequestChunks configured the encoder to always return fixed-length chunks. This then causes
// all chunks in the encapsulated message to be of the same length.
//
// If this option is enabled, the request encoder will wait for more data to complete a full chunk instead
// of sending them as fast as possible. The encoder will also use BHTTP padding to pad the final chunk if required.
func FixedLengthRequestChunks() Option {
	return func(enc *config) error {
		enc.fixedRequestChunks = true
		return nil
	}
}

// FixedLengthResponseChunks configured the encoder to always return fixed-length chunks. This then causes
// all chunks in the encapsulated message to be of the same length.
//
// If this option is enabled, the response encoder will wait for more data to complete a full chunk instead
// of sending them as fast as possible. The encoder will also use BHTTP padding to pad the final chunk if required.
func FixedLengthResponseChunks() Option {
	return func(enc *config) error {
		enc.fixedResponseChunks = true
		return nil
	}
}

// MaxResponseChunkLen sets the maximum response chunk length.
func MaxResponseChunkLen(chunkLen int) Option {
	return func(enc *config) error {
		if chunkLen < 0 {
			return fmt.Errorf("chunk length should be positive, got %d", chunkLen)
		}
		if chunkLen > rfcMaxChunkLen {
			return fmt.Errorf("chunk would exceed maximum length per RFC 9458: %d > %d", chunkLen, rfcMaxChunkLen)
		}
		enc.responseChunkLen = chunkLen
		return nil
	}
}

func WithCustomRequestEncoder(encoder *bhttp.RequestEncoder) Option {
	return func(enc *config) error {
		enc.customRequestEncoder = encoder
		return nil
	}
}

func WithCustomRequestDecoder(decoder *bhttp.RequestDecoder) Option {
	return func(enc *config) error {
		enc.customRequestDecoder = decoder
		return nil
	}
}

func WithCustomResponseEncoder(encoder *bhttp.ResponseEncoder) Option {
	return func(enc *config) error {
		enc.customResponseEncoder = encoder
		return nil
	}
}

func WithCustomResponseDecoder(decoder *bhttp.ResponseDecoder) Option {
	return func(enc *config) error {
		enc.customResponseDecoder = decoder
		return nil
	}
}
