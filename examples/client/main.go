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
	"os"
	"time"

	"github.com/confidentsecurity/ohttp"
)

func main() {
	// The OHTTP spec does not specify how the client acquires a KeyConfig,
	// here we read it from a file.
	keyConfigFile := "../gateway/keyconfig.ohttp"
	if kcf, ok := os.LookupEnv("KEY_CONFIG_FILE"); ok {
		keyConfigFile = kcf
	}

	keyConfig, err := readKeyConfigFile(keyConfigFile)
	if err != nil {
		log.Fatalf("failed to read key config file: %v", err)
	}

	// Construct a HTTP client with an OHTTP Transport
	relayURL := "http://127.0.0.1:7777"
	if rURL, ok := os.LookupEnv("RELAY_URL"); ok {
		relayURL = rURL
	}

	transport, err := ohttp.NewTransport(keyConfig, relayURL)
	if err != nil {
		log.Fatalf("failed to create ohttp transport: %v", err)
	}
	fmt.Println(transport)

	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	// construct a request.
	//
	// Note the URL, by default the Gateway only accepts requests with the ohttp.invalid
	// hostname. This can be overwritten by providing a custom ohttp.HostnameAllowlist to
	// the Gateway.
	// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.http-customized-request.http-customized-request
	req, err := http.NewRequest(http.MethodGet, "http://ohttp.invalid", nil)
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}

	// Do the request and print status code and body to stdout.
	fmt.Printf("requesting %s via OHTTP\n", req.URL)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.Fatalf("failed to close body: %v", err)
		}
	}()

	fmt.Printf("status code %d\n", resp.StatusCode)
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		log.Fatalf("failed to copy request body: %v", err)
	}
	fmt.Println()
}

func readKeyConfigFile(name string) (ohttp.KeyConfig, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return ohttp.KeyConfig{}, fmt.Errorf("failed to read file: %w", err)
	}

	var kc ohttp.KeyConfig
	err = kc.UnmarshalBinary(data)
	if err != nil {
		return ohttp.KeyConfig{}, fmt.Errorf("failed to unmarshal binary: %w", err)
	}
	return kc, nil
}
