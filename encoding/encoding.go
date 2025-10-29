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

package encoding

import (
	"context"
	"io"
	"net/http"
)

// RequestEncoder encodes HTTP requests to messages. It is up to the request encoder
// to decide whether a request should be chunked or unchunked.
//
// It is also the responsibility of the request encoder to return an appropriate
// ResponseDecoder for each request. This gives the request decoder the option to
// decide encoding per roundtrip.
type RequestEncoder interface {
	EncodeRequest(r *http.Request) (*Message, ResponseDecoder, error)
}

// RequestDecoder decodes messages to HTTP requests.
//
// it is the responsibility of the request decoder to return an appropriate ResponseEncoder
// for each request. This gives the request decoder the option to decide encoding per
// roundtrip.
type RequestDecoder interface {
	MaxChunkLen() int
	MediaType(chunked bool) []byte
	DecodeRequest(ctx context.Context, r io.Reader, chunked bool) (*http.Request, ResponseEncoder, error)
}

// ResponseEncoder encodes HTTP responses to messages. It is up to the response encoder
// to decide whether a response should be chunked or unchunked.
type ResponseEncoder interface {
	EncodeResponse(ctx context.Context, rsp *http.Response) (*Message, error)
}

// ResponseDecoder decodes messages to HTTP responses.
type ResponseDecoder interface {
	MaxChunkLen() int
	MediaType(chunked bool) []byte
	DecodeResponse(ctx context.Context, r io.Reader, chunked bool) (*http.Response, error)
}

// Message is an encoded HTTP request or response.
type Message struct {
	io.Reader
	MediaType []byte
	// Chunked indicates a message should be chunked.
	Chunked bool
	// ChunkLen is the chunk length for this message. Encoder implementations
	// should only return a chunk length greater than 16384 bytes if they
	// are certain that a request or response receiver can handle the larger
	// chunks.
	//
	// See the Draft RFC section 3 for more details:
	// https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html#name-chunked-requests-and-respon
	ChunkLen int
}
