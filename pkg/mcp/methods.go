package mcp

import (
	"agentmesh/pkg/auth"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type MCPMethod string

const (
	MethodInitialize   MCPMethod = "initialize"
	MethodToolList     MCPMethod = "tools/list"
	MethodToolCall     MCPMethod = "tools/call"
	MethodResourceList MCPMethod = "resources/list"
	MethodResourceRead MCPMethod = "resources/read"
	MethodPromptsList  MCPMethod = "prompts/list"
	MethodPromptsGet   MCPMethod = "prompts/get"
	MethodUnclassified MCPMethod = ""
)

type ToolCallParams struct {
	Name      string           `json:"name"`
	Arguments *json.RawMessage `json:"arguments,omitempty"`
}

type ResourceReadParams struct {
	URI string `json:"uri"`
}

type PromptGetParams struct {
	Name      string             `json:"name"`
	Arguments *map[string]string `json:"arguments,omitempty"`
}

type PolicyInput struct {
	TraceID     string              `json:"trace_id"`
	Agent       *auth.AgentIdentity `json:"agent"`
	Method      MCPMethod           `json:"method"`
	ToolName    string              `json:"tool_name,omitempty"`
	ResourceURI string              `json:"resource_uri,omitempty"`
	RawArgs     *json.RawMessage    `json:"raw_args,omitempty"`
	ReceivedAt  time.Time           `json:"received_at"`
}

func Normalize(env *Envelope, traceID string, agent *auth.AgentIdentity) (*PolicyInput, error) {
	if agent == nil {
		return nil, errors.New("agent identity is nil")
	}

	if env == nil || env.Method == nil {
		return nil, errors.New("envelope or method is nil")
	}

	method := MCPMethod(*env.Method)

	input := &PolicyInput{
		Agent:     agent,
		TraceID:    traceID,
		Method:     method,
		ReceivedAt: time.Now().UTC(),
	}

	switch method {
	case MethodToolCall:
		if env.Params == nil {
			return nil, errors.New("params is nil for tools/call method")
		}

		var params ToolCallParams
		if err := json.Unmarshal(*env.Params, &params); err != nil {
			return nil, fmt.Errorf("failed to  unmarshal params: %w", err)
		}

		if params.Arguments != nil {
			rawArgs := *params.Arguments

			if !json.Valid(rawArgs) {
				return nil, errors.New("invalid JSON in arguments for tools/call method")
			}

			trimmed := bytes.TrimSpace(rawArgs)

			if len(trimmed) == 0 || trimmed[0] != '{' {
				return nil, errors.New("arguments for tools/call method must be a JSON object")
			}
		}

		if strings.TrimSpace(params.Name) == "" {
			return nil, errors.New("tool name is empty for tools/call method")
		}

		input.ToolName = params.Name
		input.RawArgs = params.Arguments

	case MethodResourceRead:
		if env.Params == nil {
			return nil, errors.New("params is nil for resources/read method")
		}

		var params ResourceReadParams
		if err := json.Unmarshal(*env.Params, &params); err != nil {
			return nil, errors.New("failed to unmarshal params for resources/read method")
		}

		if strings.TrimSpace(params.URI) == "" {
			return nil, errors.New("resource URI is empty for resources/read method")
		}

		input.ResourceURI = params.URI

	default:
		input.RawArgs = env.Params
	}

	return input, nil
}
