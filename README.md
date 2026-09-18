# AgentMesh Firewall

AgentMesh Firewall is a Go-based security gateway for AI agents that communicate
with Model Context Protocol (MCP) tool providers. It authenticates incoming
requests, validates JSON-RPC 2.0 messages, normalizes MCP parameters, and
prepares requests for policy evaluation.

> **Project status:** This project is currently a library/prototype. The core
> authentication, MCP validation, normalization, and HTTP handler packages are
> implemented. A runnable server entrypoint and the OPA policy implementation
> are not available yet.

## Features

- **JSON-RPC 2.0 validation** - Validates envelopes and classifies requests,
  notifications, and responses.
- **Bearer token authentication** - Extracts tokens from the `Authorization`
  header and hashes them with SHA-256 before identity lookup.
- **In-memory identity store** - Provides a thread-safe identity resolver backed
  by `sync.RWMutex`.
- **Identity lifecycle checks** - Rejects inactive, expired, or invalid agents.
- **Trust score validation** - Ensures trust scores remain within the `0-100`
  range.
- **Request-size protection** - Limits HTTP request bodies to `1 MiB`.
- **MCP normalization** - Converts supported MCP methods such as `tools/call`
  and `resources/read` into a common policy input.
- **Policy engine contract** - Defines an interface for adding an authorization
  backend such as OPA/Rego.

## Architecture

```text
Client / AI agent
        |
        | POST + Authorization: Bearer <token> + JSON-RPC 2.0
        v
ProxyHandler
  1. HTTP method validation
  2. Token extraction and SHA-256 hashing
  3. Identity lookup and lifecycle validation
  4. 1 MiB request-body limit
  5. JSON-RPC envelope validation
  6. MCP parameter normalization
        |
        v
PolicyInput -> policy engine integration
```

## Project Structure

```text
.
├── pkg/
│   ├── auth/
│   │   ├── identity.go       # Token and identity validation
│   │   └── identity_test.go
│   ├── mcp/
│   │   ├── envelope.go       # JSON-RPC 2.0 validation and classification
│   │   ├── methods.go        # MCP methods and request normalization
│   │   ├── envelope_test.go
│   │   └── methods_test.go
│   ├── policy/
│   │   ├── engine.go         # Policy engine interface and decisions
│   │   └── opa.go            # OPA integration placeholder
│   └── proxy/
│       ├── handler.go        # HTTP request pipeline
│       └── handler_test.go
├── go.mod
├── go.sum
└── README.md
```

## Requirements

- Go `1.26.4` or a compatible newer version, as specified in `go.mod`.
- Git, if you are cloning the repository.

## Installation

```bash
git clone <repository-url>
cd AgentMesh-Firewall
go mod download
```

This repository does not currently contain a `main` package. Therefore,
`go run ./cmd/proxy` is not available yet. The packages can be imported by
another Go service, or a server entrypoint can be added under `cmd/proxy`.

## Running Tests

Run all tests:

```bash
go test ./...
```

Run tests with verbose output and disable the test cache:

```bash
go test -count=1 -v ./...
```

The test suite includes unit tests for authentication, identity validation,
JSON-RPC envelopes, MCP normalization, and HTTP handler behavior using
`net/http/httptest`.

## Using the Proxy Handler

The proxy handler expects an `auth.IdentityResolver`. A minimal setup looks like
this:

```go
store := auth.NewMemoryIdentityStore()
rawToken := "example-token"

store.Set(&auth.AgentIdentity{
    AgentID:       "agent-001",
    TenantID:      "tenant-001",
    KeyHash:       auth.HashKey(rawToken),
    Status:        auth.StatusActive,
    TrustScore:    80,
    AllowedScopes: []string{"tools:read"},
})

handler := proxy.NewProxyHandler(store)
```

Example request:

```http
POST /mcp HTTP/1.1
Authorization: Bearer example-token
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}}}
```

## Policy Integration

The `pkg/policy.Engine` interface is the extension point for authorization
decisions. A production policy implementation should evaluate the normalized
`mcp.PolicyInput` and enforce:

- allowed MCP methods and tool scopes;
- tenant and agent boundaries;
- trust-score requirements for sensitive tools; and
- argument and resource URI validation.

The current proxy handler returns the normalized policy input as JSON. It does
not yet forward requests to a downstream MCP server or enforce an OPA/Rego
decision.

## Security Notes

- Never log raw Bearer tokens.
- Replace the in-memory identity store before production deployment.
- Add and configure a real policy engine before exposing the handler to
  untrusted users.
- Keep the request-size limit enabled when adding downstream forwarding.

## License

No license has been specified yet.
