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

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

func main() {
	// Fake relay for local development using httputil.ReverseProxy.

	// DO NOT USE IN PRODUCTION!
	// Production OHTTP relays should be ran by third parties.

	port := "7777"
	if p, ok := os.LookupEnv("RELAY_PORT"); ok {
		port = p
	}
	gatewayURLRaw := "http://127.0.0.1:8888"
	if gURL, ok := os.LookupEnv("GATEWAY_URL"); ok {
		gatewayURLRaw = gURL
	}

	gatewayURL, err := url.Parse(gatewayURLRaw)
	if err != nil {
		log.Fatalf("invalid gateway url: %v", err)
	}

	// configure proxy to log bodies (it will be binary data)
	proxy := httputil.NewSingleHostReverseProxy(gatewayURL)
	prevDirector := proxy.Director
	// nosemgrep: go.lang.security.reverseproxy-director.reverseproxy-director
	proxy.Director = func(r *http.Request) {
		log.Printf("%s request for %s\n", r.Method, r.URL.Path)
		r.Body = &loggingReader{
			prefix: "REQ",
			bdy:    r.Body,
		}
		prevDirector(r)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Body = &loggingReader{
			prefix: "RESP",
			bdy:    resp.Body,
		}
		return nil
	}

	log.Printf("running relay...")
	// nosemgrep: go.lang.security.audit.net.use-tls.use-tls
	err = http.ListenAndServe(":"+port, proxy)
	if err != nil {
		log.Fatalf("failed to run relay: %v", err)
	}
}

type loggingReader struct {
	prefix string
	bdy    io.ReadCloser
}

func (r *loggingReader) Read(p []byte) (int, error) {
	if r.bdy == nil {
		return 0, io.EOF
	}

	defer func() {
		// print up to 128 bytes of this read.
		pLen := min(128, len(p))
		fmt.Printf("%s %s\n", r.prefix, p[:pLen])
	}()

	n, err := r.bdy.Read(p)
	if err != nil {
		return n, err
	}
	return n, err
}

func (r *loggingReader) Close() error {
	if r.bdy == nil {
		return nil
	}

	return r.bdy.Close()
}
