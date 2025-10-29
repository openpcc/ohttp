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
	"fmt"

	"github.com/confidentsecurity/ohttp/encoding"
	"github.com/confidentsecurity/ohttp/encoding/bhttp"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type gatewayCfg struct {
	decoder      encoding.RequestDecoder
	errorHandler ErrorHandler
	reqValidator RequestValidator
	tracer       trace.Tracer
}

func defaultGatewayConfig() (*gatewayCfg, error) {
	defaultDecoder, err := bhttp.NewRequestDecoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create default request decoder: %w", err)
	}

	return &gatewayCfg{
		decoder:      defaultDecoder,
		errorHandler: defaultErrorHandler(),
		reqValidator: NewHostnameAllowlist(),
		tracer:       noop.Tracer{},
	}, nil
}

// GatewayOption configures a gateway.
type GatewayOption func(cfg *gatewayCfg) error

// WithRequestDecoder provides a custom request decoder for a gateway.
func WithRequestDecoder(dec encoding.RequestDecoder) GatewayOption {
	return func(cfg *gatewayCfg) error {
		if dec == nil {
			return errors.New("nil request decoder")
		}
		cfg.decoder = dec
		return nil
	}
}

// WithErrorHandler provides a custom error handler for a gateway.
func WithErrorHandler(errHandler ErrorHandler) GatewayOption {
	return func(cfg *gatewayCfg) error {
		if errHandler == nil {
			return errors.New("nil error handler")
		}
		cfg.errorHandler = errHandler
		return nil
	}
}

// WithRequestValidator provides a custom request validator for a gateway. Set
// the validator to nil to disable request validation. Be careful as clients can
// send requests with any hostname.
func WithRequestValidator(validator RequestValidator) GatewayOption {
	return func(cfg *gatewayCfg) error {
		cfg.reqValidator = validator
		return nil
	}
}

// WithOTELTracer provides a custom request validator for a gateway. Set
// the validator to nil to disable request validation. Be careful as clients can
// send requests with any hostname.
func WithOTELTracer(tracer trace.Tracer) GatewayOption {
	return func(cfg *gatewayCfg) error {
		cfg.tracer = tracer
		return nil
	}
}
