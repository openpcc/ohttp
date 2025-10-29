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
	"errors"
	"net/http"

	"github.com/confidentsecurity/ohttp/encoding"
	"go.opentelemetry.io/otel/trace"
)

type transportCfg struct {
	httpClient *http.Client
	encoder    encoding.RequestEncoder
	tracer     trace.Tracer
}

// TransportOption allows for the configuration of Transports.
type TransportOption func(cfg *transportCfg) error

// WithHTTPClient provides a custom http client to the Transport.
func WithHTTPClient(c *http.Client) TransportOption {
	return func(cfg *transportCfg) error {
		if c == nil {
			return errors.New("nil http client")
		}
		cfg.httpClient = c
		return nil
	}
}

// WithRequestEncoder provides a custom request encoder to the Transport.
func WithRequestEncoder(enc encoding.RequestEncoder) TransportOption {
	return func(cfg *transportCfg) error {
		if enc == nil {
			return errors.New("nil request encoder")
		}
		cfg.encoder = enc
		return nil
	}
}

// WithOTELTransportTracer provides a custom otel tracer for the transport to use for tracing
func WithOTELTransportTracer(tracer trace.Tracer) TransportOption {
	return func(cfg *transportCfg) error {
		if tracer == nil {
			return errors.New("nil tracer")
		}
		cfg.tracer = tracer
		return nil
	}
}
