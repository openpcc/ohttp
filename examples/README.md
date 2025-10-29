# Example: Client and Gateway with a fake relay

The examples in these directories show you how to use the `ohttp` together with
regular `net/http` types to send requests/responses via OHTTP.

This example uses a fake relay, in production projects you will want to use a third-party service
to provide a relay.

The easiest way to explore this example is work backwards and begin with the `gateway` command. All packages can be ran by running `go run main.go` in their respective directories.

The `gateway` package:
1. Sets up the HPKE keys required for secure communication.
2. Writes the `ohttp.KeyConfig` to a file so that the client can retrieve them.
3. Sets up a `ohttp.Gateway` and wraps a `"hello world"` handler using its middleware.
4. Runs a basic `http.Server` to serve the gateway.

Next up is the `fakerelay`, this package:
1. Sets up a `httputil.ReverseProxy` that logs request/response bodies. This way we can see that they actually get encrypted.
2. Runs a basic `http.Server` that serves the proxy.

Finally, there is the `client`, it:
1. Loads the `ohttp.KeyConfig` from the file the gateway created.
2. Sets up a `ohttp.Transport` that uses the KeyConfig.
3. Sets up a regular `http.Client` that uses the `ohttp.Transport` as its transport.
4. Makes a HTTP request to the `fakerelay`.

The client HTTP requests goes through the following steps:
1. `http.Client` receives a request and forwards it to `ohttp.Transport`.
2. `ohttp.Transport` encapsulates the request to an OHTTP request.
3. `ohttp.Transport` sends this request to `fakerelay` server.
4. `fakerelay` forwards the request to the `gateway` server.
5. `ohttp.Gateway` middleware decapsulates the OHTTP request and forwards it to the `handler` function.
6. `handler` function writes a regular response.
7. `ohttp.Gateway` encapsulates the response to an OHTTP response.
8. `fakerelay` forwards the response to `client` transport.
9. `ohttp.Transport` decapsulates the OHTTP response and forwards it to the `http.Client`.
