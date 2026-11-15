# AgentMesh Firewall

Version 1.0.0

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
- Configurable request and downstream response size limits.
- MCP normalization for `tools/call` and `resources/read`.
- OPA/Rego authorization with default-deny MCP method allowlisting, tenant
  isolation, trust-score, tool-scope, and sensitive-path checks.
- Downstream HTTP dispatch with hop-by-hop and gateway authorization headers
  removed.
- Structured JSON audit logging.
- Structured JSON-RPC errors with remediation hints and trace IDs.
- Graceful shutdown on `SIGINT` and `SIGTERM`.

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

The firewall listens on `http://127.0.0.1:9999` and forwards authorized
requests to `http://127.0.0.1:9000/mcp` by default. Configuration is loaded
with this precedence:

```text
CLI flags > AGENTMESH_* environment variables > agentmesh.yaml > safe defaults
```

Copy [agentmesh.example.yaml](agentmesh.example.yaml) to `agentmesh.yaml`,
then replace the placeholder `token_hash` with the SHA-256 hash of a
high-entropy bearer token. Never place the raw token in the configuration file.

The default policy path is relative to the repository root. Use an absolute
path when starting the binary from another working directory.

The proxy also exposes unauthenticated operational endpoints:

```text
GET /healthz  -> 200 {"status":"ok"}
GET /readyz   -> 200 {"status":"ready"}
```

`/readyz` returns `503` when the policy engine, dispatcher, or downstream URL
is not configured correctly.

### Configuration

Supported YAML fields include:

| Field | Description |
| --- | --- |
| `listen_addr` | HTTP listen address |
| `downstream_url` | Downstream MCP endpoint |
| `policy_path` | OPA/Rego policy file |
| `rate_limit_per_minute` | Per-agent request limit |
| `downstream_timeout` | Downstream request timeout |
| `max_request_body_bytes` | Maximum inbound request size |
| `max_response_body_bytes` | Maximum downstream response size |
| `read_header_timeout`, `read_timeout`, `write_timeout`, `idle_timeout` | HTTP server timeouts |
| `identities` | Configured agent identity records |

The following environment variables override matching YAML values:

```text
AGENTMESH_LISTEN_ADDR
AGENTMESH_DOWNSTREAM_URL
AGENTMESH_POLICY_PATH
AGENTMESH_RATE_LIMIT_PER_MINUTE
AGENTMESH_DOWNSTREAM_TIMEOUT
AGENTMESH_READ_HEADER_TIMEOUT
AGENTMESH_READ_TIMEOUT
AGENTMESH_WRITE_TIMEOUT
AGENTMESH_IDLE_TIMEOUT
```

CLI overrides:

```bash
go run ./cmd/proxy --config ./agentmesh.yaml --listen 127.0.0.1:9999
go run ./cmd/proxy --downstream http://localhost:9000/mcp
go run ./cmd/proxy --policy ./pkg/policy/agent_mesh.rego
go run ./cmd/proxy --version
```

## Example request

Configure an active identity in `agentmesh.yaml` and use its corresponding
high-entropy token.

```bash
curl -i http://localhost:9999/mcp ^
  -H "Authorization: Bearer <configured-token>" ^
  -H "Content-Type: application/json" ^
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp\"}}}"
```

The request is allowed when it satisfies the policy and the downstream
response is returned to the client. Policy, validation, authentication, and
downstream failures are returned as structured JSON-RPC 2.0 errors with a
remediation hint and trace ID. Notifications are forwarded without a response
body and return HTTP 202.

Example policy denial:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "Request blocked by AgentMesh security policy",
    "data": {
      "violation": "tool_not_permitted",
      "action": "Use an allowed tool.",
      "retryable": false,
      "trace_id": "trace-123"
    }
  }
}
```

The bundled policy explicitly supports `initialize`, `notifications/initialized`,
`tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`,
and `prompts/get`. Unknown methods are denied by default. Resource reads reject
path traversal and sensitive locations such as `.env`, `.ssh`, `.git/config`,
`/etc`, and `C:\Windows`.

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

Run the race detector when a CGO-compatible C compiler is installed:

```bash
CGO_ENABLED=1 go test -race ./...
```

## Project structure

```text
.
├── cmd/
│   ├── mock_mcp/             # Local downstream MCP server
│   └── proxy/                # Firewall server entrypoint
├── pkg/
│   ├── auth/                 # Authentication and identity validation
│   ├── config/               # YAML, environment, and CLI configuration
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

- The example identity hash is a placeholder for local testing only.
- Replace the in-memory identity store with a persistent, managed identity
  provider for multi-instance production use.
- Configure downstream URLs and credentials outside source code for production.
- Do not log raw bearer tokens.
- Keep policy files and identity configuration under controlled deployment
  ownership.
- The default identity store is process-local; multiple proxy instances need a
  shared identity and rate-limit strategy.

## License

No license has been specified yet.
