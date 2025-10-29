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
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
)

// ErrorCode is the error code of a gateway error.
type ErrorCode int

// Error codes returned by the Gateway.
const (
	ErrorCodeRequestIO  ErrorCode = 1
	ErrorCodeResponseIO ErrorCode = 2

	ErrorCodeInvalidRequestHeader ErrorCode = 100
	ErrorCodeKeyNotFound          ErrorCode = 101
	ErrorCodeInvalidKey           ErrorCode = 102
	ErrorCodeInactiveKey          ErrorCode = 103

	ErrorCodeInvalidRequestContentType ErrorCode = 200
	ErrorCodeRequestDecoding           ErrorCode = 201
	ErrorCodeInvalidRequest            ErrorCode = 202

	ErrorCodeResponseEncoding   ErrorCode = 300
	ErrorCodeResponseEncryption ErrorCode = 301
)

// GatewayError is an error that occurred during the handling of an encapsulated
// OHTTP request. Gateway error handlers can check for this error and derive more
// detailed information.
type GatewayError struct {
	Code ErrorCode
	Err  error
}

// IsGeneralError indicates whether the error is a general error.
func (e GatewayError) IsGeneralError() bool {
	return e.Code >= 0 && e.Code < 100
}

// IsKeyError indicates whether the error has a key-related error code.
func (e GatewayError) IsKeyError() bool {
	return e.Code >= 100 && e.Code < 200
}

// IsRequestError indicates whether the error has a request-related error code.
func (e GatewayError) IsRequestError() bool {
	return e.Code >= 200 && e.Code < 300
}

// IsResponseError indicates whether the error has a response-related error code.
func (e GatewayError) IsResponseError() bool {
	return e.Code >= 300 && e.Code < 400
}

func (e GatewayError) Error() string {
	return strconv.Itoa(int(e.Code)) + ": " + e.Err.Error()
}

func (e GatewayError) Unwrap() error {
	return e.Err
}

// ResponseStatusError is an error code that was discovered during the transport (decap) of an OHTTP response.
// This helper type is used for passing error state around should an encapsulated response return
// a non-200 status code.
type ResponseStatusError struct {
	StatusCode int
	Err        error
	// TODO (CS-1053): Consider parsing application/problem+json errors here for more robust error messages/handling.
}

func (e ResponseStatusError) Error() string {
	return strconv.Itoa(e.StatusCode) + ": " + e.Err.Error()
}

func (e ResponseStatusError) Unwrap() error {
	return e.Err
}

func (e ResponseStatusError) IsClientError() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// JSONProblemErrorHandler writes errors as application/json+problem responses and optionally logs error
// with the provided LogFunc.
type JSONProblemErrorHandler struct {
	LogFunc func(err error)
}

func defaultErrorHandler() *JSONProblemErrorHandler {
	return &JSONProblemErrorHandler{
		LogFunc: func(err error) {
			log.Printf("error: %v", err)
		},
	}
}

// HandleError logs the error and writes a JSON problem response if no headers have been written.
func (h *JSONProblemErrorHandler) HandleError(w http.ResponseWriter, headersWritten bool, err error) {
	if h.LogFunc != nil {
		h.LogFunc(err)
	}

	if headersWritten {
		return
	}

	code := http.StatusInternalServerError
	ianaType := "about:blank"
	title := "See HTTP Status Code"
	gwErr := GatewayError{}
	if errors.As(err, &gwErr) {
		switch {
		case gwErr.IsKeyError():
			code = http.StatusBadRequest
			ianaType = "https://iana.org/assignments/http-problem-types#ohttp-key"
			title = "Oblivious HTTP key configuration not acceptable"
		case gwErr.Code == ErrorCodeRequestIO || gwErr.IsRequestError():
			code = http.StatusBadRequest
		default:
		}
	}

	problem := struct {
		Type  string `json:"type"`
		Title string `json:"title"`
	}{
		Type:  ianaType,
		Title: title,
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	if err := enc.Encode(problem); err != nil {
		if h.LogFunc != nil {
			h.LogFunc(err)
		}
	}
}
