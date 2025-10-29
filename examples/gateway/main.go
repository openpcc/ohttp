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
	"log"
	"net/http"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/ohttp"
)

func main() {
	// First we need some keys. In this example we'll generate the keys, but in
	// reality you will want to persist them somewhere so you can use the same keys
	// between restarts.
	kemID := hpke.KEM_P256_HKDF_SHA256
	pubKey, privKey, err := kemID.Scheme().GenerateKeyPair()
	if err != nil {
		log.Fatalf("failed to generate keypair: %v", err)
	}

	// The KeyPair is what we provide to the Gateway, the KeyConfig to the client.
	keyPair := ohttp.KeyPair{
		SecretKey: privKey,
		KeyConfig: ohttp.KeyConfig{
			KeyID:     1,
			KemID:     kemID,
			PublicKey: pubKey,
			SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
				{
					KDFID:  hpke.KDF_HKDF_SHA256,
					AEADID: hpke.AEAD_AES128GCM,
				},
			},
		},
	}

	// The OHTTP spec does not specify how the client acquires a KeyConfig,
	// here we write it to a file which the client can then load.
	keyConfigFile := "keyconfig.ohttp"
	if kcf, ok := os.LookupEnv("KEY_CONFIG_FILE"); ok {
		keyConfigFile = kcf
	}

	err = writeKeyConfigFile(keyConfigFile, keyPair.KeyConfig)
	if err != nil {
		log.Fatalf("failed to write key config file: %v", err)
	}

	// Create the gateway and wrap the handler in its middleware.
	gateway, err := ohttp.NewGateway(keyPair)
	if err != nil {
		log.Fatalf("failed to create gateway: %v", err)
	}

	h := ohttp.Middleware(gateway, http.HandlerFunc(handler))

	// Run the server.
	port := "8888"
	if p, ok := os.LookupEnv("GATEWAY_PORT"); ok {
		port = p
	}

	log.Printf("running gateway...")
	// nosemgrep: go.lang.security.audit.net.use-tls.use-tls
	err = http.ListenAndServe(":"+port, h)
	if err != nil {
		log.Fatalf("failed to run relay: %v", err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s request for %s\n", r.Method, r.URL.Path)
	w.Write([]byte("Hello world!"))
}

func writeKeyConfigFile(name string, kc ohttp.KeyConfig) error {
	data, err := kc.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal keyconfig to binary: %w", err)
	}

	err = os.WriteFile(name, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}
