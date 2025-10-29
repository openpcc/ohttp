# OHTTP - Oblivious HTTP Client and Gateway written in Go

This package implements OHTTP in Go. It provides both a Transport (Client) and a Gateway.

`ohttp` is a Go package that provides an Oblivious HTTP (OHTTP) client and Gateway as specified in [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html) and [draft-ietf-ohai-chunked-ohttp-03](https://datatracker.ietf.org/doc/draft-ietf-ohai-chunked-ohttp/).

## Features

- Easy to use:
  - The Transport implements `http.RoundTripper` and can be plugged into a regular `*http.Client`. No need to adapt the rest of your app to send requests over OHTTP.
  - The Gateway can be used as a Middleware to wrap an existing `http.Handler`. The handler
  can speak regular HTTP while the middleware translates to OHTTP.
- Supports both unchunked (known length) and unchunked (unknown length) requests/responses.
- Defaults to `bhttp` encoding but accepts custom encodings.
- Overwrite every aspect of the roundtrip via custom encodings.

## On OHTTP relays

An OHTTP Relay sits between an OHTTP Client and a Gateway. The relay keeps the identity of clients from the Gateway. For OHTTP to function as a system, it is fundamental that the relay is ran by a third party.

This package does not include a relay and assumes you have a third party relay in production environments. [Cloudflare](https://developers.cloudflare.com/privacy-gateway/), [Fastly](https://docs.fastly.com/products/oblivious-http-relay) and [oblivious.network](https://oblivious.network/) all offer OHTTP Relays as a service.

If you need a fake relay for local testing we advise you to use a general purpose proxy like `httputil.ReverseProxy`. This won't provide any anonymity, but your requests will at least follow a similar path.

Real world OHTTP Relays can be more constrained than a general purpose proxy, so be sure to verify the constraints on the relay you're planning to use.

## Gateway as a dedicated server

The Gateway can be run in two ways:
- Combined Gateway and target resource in a single server.
- Dedicated Gateway and target resource servers.

The Gateway can be combined with the `httputil.ReverseProxy` to redirect requests to the target resource
server. See the example below.

```go
// Create the gateway and wrap the handler in its middleware.
gateway, err := ohttp.NewGateway(keyPair)
if err != nil {
  log.Fatalf("failed to create gateway: %v", err)
}

// Create a proxy that redirects requests to an external URL.
targetURL, err := url.Parse("https://example.com")
if err != nil {
  log.Fatalf("failed to parse url: %v", err)
}

proxy := httputil.NewSingleHostReverseProxy(targetURL)

// Wrap the proxy in the ohttp middleware.
h := ohttp.Middleware(gateway, http.HandlerFunc(proxy))

// h can now be used as the handler in a http.Server.
```

The above example only redirects to a single host (`example.com`). If you want the gateway to redirect to multiple hosts, and want the client
to provide the hostname, look into the `ohttp.NewHostnameAllowlist` and `ohttp.WithRequestValidator` functions.

## Example: Client and service over OHTTP

See [`examples/README.md`](examples/README.md) for a local example that runs both the Client, the Gateway and a fake relay.


## Comparison to alternative packages

Below we compare the features of this package to two other Go OHTTP packages.

### `chris-wood/ohttp-go`

A great reference implementation by one of the authors of the OHTTP RFC. It's a library that provides both a client and a gateway.

| Feature | `confidentsecurity/ohttp` | `chris-wood/ohttp-go` | Notes |
| ------- | ------------------------- | --------------------- | ----- |
| Key rotation  | Keys are sourced on demand via an injectable function | Gateway is initialized with a list of static keys |
| Key distribution | - | - | RFC 9458 explicitly leaves this unspecified |
| Hardware support | Allows for injection of custom `HPKE` components | Hard dependency on `cloudflare/circl/hpke` |
| Unchunked messages | X | X |
| Chunked messages per [draft RFC](https://datatracker.ietf.org/doc/html/draft-ietf-ohai-chunked-ohttp-03) | X | - |
| Custom message encodings | X | X |
| Integration | `http.Transport` and `http.Handler` compatible middleware. | Requires glue code to integrate into an app or client. |

### `cloudflare/privacy-gateway-server-go`

A command that wraps the `chris-wood/ohttp-go` to provide a gateway you can run as a dedicated server. Since this is a command, we'll compare it to the recommended way to run the `confidentsecurity/ohttp` Gateway as [a dedicated server](#gateway-as-a-dedicated-server).

| Feature | `confidentsecurity/ohttp` | `cloudflare/privacy-gateway-server-go` | Notes |
| ------- | ------------------------- | -------------------------------------- | ----- |
| Key rotation  | Keys are sourced on demand via an injectable function | Gateway is initialized with a list of static keys | |
| Key distribution | - | Key Configs can be retrieved via endpoint. | RFC 9458 explicitly leaves this unspecified. | |
| Hardware support | Allows for injection of custom `HPKE` components | Hard dependency on `cloudflare/circl/hpke` | |
| Unchunked messages | X | X | |
| Chunked messages per [draft RFC](https://datatracker.ietf.org/doc/html/draft-ietf-ohai-chunked-ohttp-03) | X | - | |
| Custom message encodings | X | X | |
| Integration | Need to write your own command. | Provides a command. |

## Found a security issue?

Reach out to [security@confidentsecurity.com](mailto:security@confidentsecurity.com).

## Development

Run tests with `go test ./...`

Run the examples with `go run ./examples/client` etc.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Contributing

For guidelines on contributing to this project, please see [CONTRIBUTING.md](CONTRIBUTING.md).
