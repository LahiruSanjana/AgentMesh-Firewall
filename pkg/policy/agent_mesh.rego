package agentmesh.authz

default allow := false
default reason := "access denied by security policy"

violations[msg] {
    input.agent.trust_score < 70
    msg := "insufficient_trust_score"
}

violations[msg] {
    lower(input.agent.status) != "active"
    msg := "agent_status_not_active"
}

tool_is_allowed {
    input.agent.scopes[_] == input.tool_name
}

violations[msg] {
    input.method == "tools/call"
    not tool_is_allowed
    msg := "tool_not_permitted"
}

violations[msg] {
    input.method == "resources/read"
    is_string(input.resource_uri)
    contains(input.resource_uri, "..")
    msg := "path_traversal_detected"
}

allow { count(violations) == 0}

reason = "access granted" { allow }
reason = msg { count(violations) > 0; msg := concat(", ", violations) }