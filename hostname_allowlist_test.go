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

package ohttp_test

import (
	"net/http"
	"testing"

	"github.com/confidentsecurity/ohttp"
	"github.com/stretchr/testify/require"
)

func TestHostnameAllowlist(t *testing.T) {
	tests := map[string]struct {
		hostnames []string
		url       string
		wantErr   bool
	}{
		"ok, default hostname": {
			hostnames: nil,
			url:       "http://ohttp.invalid/test",
			wantErr:   false,
		},
		"ok, explicit hostname": {
			hostnames: []string{"example.com"},
			url:       "http://example.com/test",
			wantErr:   false,
		},
		"ok, explicit hostnames": {
			hostnames: []string{"example.com", "example.org", "127.0.0.1"},
			url:       "http://127.0.0.1/test",
			wantErr:   false,
		},
		"fail, default hostname": {
			hostnames: nil,
			url:       "http://example.com/test",
			wantErr:   true,
		},
		"fail, explicit hostname": {
			hostnames: []string{"example.com"},
			url:       "http://ohttp.invalid/test",
			wantErr:   true,
		},
		"fail, explicit hostnames": {
			hostnames: []string{"example.com", "example.org", "127.0.0.1"},
			url:       "http://ohttp.invalid/test",
			wantErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			list := ohttp.NewHostnameAllowlist(tc.hostnames...)

			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			require.NoError(t, err)

			err = list.ValidRequest(req)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ohttp.ErrHostnameNotAllowed)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
