package telemetry

import (
	"encoding/json"
	"log"
	"time"
)

type AuditLog struct {
	Timestamp  string `json:"timestamp"`
	AgentID    string `json:"agent_id,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	Method     string `json:"method"`
	ToolName   string `json:"tool_name,omitempty"`
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason,omitempty"`
	StatusCode int    `json:"status_code"`
	ClientIP   string `json:"client_ip"`
}

type AuditLogger struct{}

func NewAuditLogger() *AuditLogger {
	return &AuditLogger{}
}

func (l *AuditLogger) Log(entry AuditLog) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[ERROR] failed to marshal audit log: %v", err)
		return
	}
	log.Println(string(data))
}