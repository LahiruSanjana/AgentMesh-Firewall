package agentmesh.authz

default allow := false
default reason := "access denied by security policy"
default action := "Review the policy violation and retry with an allowed MCP request."
default retryable := false

standard_method(method) { method == "initialize" }
standard_method(method) { method == "notifications/initialized" }
standard_method(method) { method == "tools/list" }
standard_method(method) { method == "tools/call" }
standard_method(method) { method == "resources/list" }
standard_method(method) { method == "resources/read" }
standard_method(method) { method == "prompts/list" }
standard_method(method) { method == "prompts/get" }

violations[msg] {
    not standard_method(input.method)
    msg := "method_not_allowed"
}
violations[msg] {
    input.identity.tenant_id == ""
    msg := "tenant_missing"
}
violations[msg] {
    input.target_tenant != ""
    input.identity.tenant_id != input.target_tenant
    msg := "tenant_scope_violation"
}
violations[msg] {
    input.identity.trust_score < 70
    msg := "insufficient_trust_score"
}
violations[msg] {
    lower(input.identity.status) != "active"
    msg := "agent_status_not_active"
}
tool_is_allowed { input.identity.allowed_scopes[_] == input.tool_name }
violations[msg] {
    input.method == "tools/call"
    not tool_is_allowed
    msg := "tool_not_permitted"
}

normalized_uri := lower(replace(input.resource_uri, "\\", "/"))
violations[msg] {
    input.method == "resources/read"
    contains(normalized_uri, "..")
    msg := "path_traversal_detected"
}
violations[msg] {
    input.method == "resources/read"
    sensitive_path
    msg := "sensitive_path_blocked"
}
sensitive_path { contains(normalized_uri, ".env") }
sensitive_path { contains(normalized_uri, ".ssh") }
sensitive_path { contains(normalized_uri, ".git/config") }
sensitive_path { startswith(normalized_uri, "/etc/") }
sensitive_path { startswith(normalized_uri, "c:/windows/") }

allow { count(violations) == 0 }
reason := "access granted" { allow }
reason := concat(", ", violations) { count(violations) > 0 }
action := "Use a supported MCP method." { violations["method_not_allowed"] }
action := "Provide a non-empty tenant identity or configure the correct tenant scope." { violations["tenant_missing"] }
action := "Use a resource belonging to the authenticated tenant." { violations["tenant_scope_violation"] }
action := "Use an allowed tool or update the tool allowlist." { violations["tool_not_permitted"] }
action := "Use a safe normalized resource path outside sensitive system and credential locations." { violations["path_traversal_detected"] }
action := "Use a safe resource path outside sensitive system and credential locations." { violations["sensitive_path_blocked"] }
