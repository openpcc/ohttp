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

const (
	// RequestMediaType is the media type for an OHTTP Request per RFC 9458.
	RequestMediaType = "message/ohttp-req"
	// ResponseMediaType is the media type for an OHTTP Response per RFC 9458.
	ResponseMediaType = "message/ohttp-res"
	// ChunkedRequestMediaType is the media type for a Chunked OHTTP Request per
	// the Chunked Oblivious HTTP Messages Draft RFC.
	ChunkedRequestMediaType = "message/ohttp-chunked-req"
	// ChunkedResponseMediaType is the media type for a Chunked OHTTP Response per
	// the Chunked Oblivious HTTP Messages Draft RFC.
	ChunkedResponseMediaType = "message/ohttp-chunked-res"
)

// isChunkedTransferEncoding checks if chunked is the final transfer encoding.
// Transfer encodings are processed in reverse order of their appearance in
// the array (unwound), so chunked must be at position 0 to be the final
// encoding applied.
func isChunkedTransferEncoding(enc []string) bool {
	return len(enc) > 0 && enc[0] == "chunked"
}
