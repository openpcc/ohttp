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
)

// ErrHostnameNotAllowed indicates a hostname is not allowed.
var ErrHostnameNotAllowed = errors.New("hostname not allowed")

// DefaultAllowedHostname is the hostname that will be added to an otherwise empty [HostnameAllowList].
//
// This hostname is guaranteed to be non-routable due to the .invalid TLD. This way you need to pick an
// explicit Target Resource hostname when using the Gateway together with a proxy.
const DefaultAllowedHostname = "ohttp.invalid"

// HostnameAllowlist is a [RequestValidator] that checks the hostname on a decapsulated
// request against the hostnames in the list.
type HostnameAllowlist struct {
	hostnames map[string]struct{}
}

// NewHostnameAllowlist creates new HostnameAllowList with the given hostnames.
//
// If no hostnames are provided, this function will automatically add [DefaultAllowedHostname].
func NewHostnameAllowlist(hostnames ...string) HostnameAllowlist {
	list := HostnameAllowlist{
		hostnames: make(map[string]struct{}),
	}
	for _, hn := range hostnames {
		list.hostnames[hn] = struct{}{}
	}

	if len(list.hostnames) == 0 {
		list.hostnames[DefaultAllowedHostname] = struct{}{}
	}

	return list
}

// ValidRequest checks if the given request has a hostname that is allowed. If the hostname
// is on the list, the request will be valid, if it's not on the list the request will be
// invalid and [ErrHostnameNotAllowed] will be returned.
func (l HostnameAllowlist) ValidRequest(r *http.Request) error {
	_, ok := l.hostnames[r.Host]
	if !ok {
		return ErrHostnameNotAllowed
	}
	return nil
}
