# AgentMesh Firewall

AgentMesh Firewall is a Go security gateway for AI agents that communicate
with Model Context Protocol (MCP) tool providers. It authenticates requests,
validates JSON-RPC 2.0 messages, normalizes MCP parameters, evaluates an
OPA/Rego policy, and forwards authorized requests to a downstream MCP service.

## Features

- JSON-RPC 2.0 envelope validation and message classification.
- Bearer-token authentication with SHA-256 key-hash lookup.
- Thread-safe in-memory identity store with status, expiry, and trust-score
  validation.
- Per-agent rate limiting.
- 1 MiB request-body limit.
- MCP normalization for `tools/call` and `resources/read`.
- OPA/Rego authorization with tenant, trust-score, tool-scope, and path
  traversal checks.
- Downstream HTTP dispatch with hop-by-hop and gateway authorization headers
  removed.
- JSON audit logging.

## Requirements

- Go 1.26.4 or newer.
- Git.

## Installation

```bash
git clone <repository-url>
cd AgentMesh-Firewall
go mod download
```

## Running locally

Start the mock downstream MCP server in one terminal:

```bash
go run ./cmd/mock_mcp
```

Start the firewall in another terminal:

```bash
go run ./cmd/proxy
```

The firewall listens on `http://localhost:9999` and forwards authorized
requests to `http://localhost:9000/mcp`. These addresses, demo identities,
and the rate limit are configured in [cmd/proxy/main.go](cmd/proxy/main.go).

The proxy currently reads the policy using a relative path, so run commands
from the repository root.

## Example request

The active demo identity uses the token `ak_live_valid_123456`.

```bash
curl -i http://localhost:9999/mcp ^
  -H "Authorization: Bearer ak_live_valid_123456" ^
  -H "Content-Type: application/json" ^
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp\"}}}"
```

The request is allowed when it satisfies the policy and the downstream
response is returned to the client. The suspended demo identity is rejected
with HTTP 403.

## Running tests

Run all tests:

```bash
go test ./...
```

Run tests without using the test cache:

```bash
go test -count=1 -v ./...
```

Run static checks:

```bash
go vet ./...
go build ./...
```

## Project structure

```text
.
├── cmd/
│   ├── mock_mcp/             # Local downstream MCP server
│   └── proxy/                # Firewall server entrypoint
├── pkg/
│   ├── auth/                 # Authentication and identity validation
│   ├── limiter/              # Per-key rate limiting
│   ├── mcp/                  # JSON-RPC and MCP normalization
│   ├── policy/               # Policy interface, OPA engine, and Rego policy
│   ├── proxy/                # HTTP handler and downstream dispatcher
│   └── telemetry/            # Audit logging
├── go.mod
├── go.sum
└── README.md
```

## Security notes

- The demo credentials in `cmd/proxy/main.go` are for local testing only.
- Replace the in-memory identity store with a persistent, managed identity
  provider before production use.
- Configure downstream URLs and credentials outside source code for production.
- Do not log raw bearer tokens.
- Review and harden the Rego policy before exposing the service to untrusted
  clients.

## License

No license has been specified yet.
