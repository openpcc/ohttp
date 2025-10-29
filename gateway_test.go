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
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGatewayAsDedicatedServer(t *testing.T) {
	t.Run("ok, gateway as dedicated server", func(t *testing.T) {
		// run the target resource server.
		targetResource := runHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world!"))
		}))

		// create the dedicated gateway server.
		targetURL, err := url.Parse(targetResource)
		require.NoError(t, err)

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		transport := setup(t, nil, true, proxy)

		client := http.Client{
			Timeout:   300 * time.Second,
			Transport: transport,
		}

		req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid/", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		requireReadAll(t, resp.Body, "hello world!")
	})
}
