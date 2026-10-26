package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		response := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"content": []map[string]string{
					{
						"type": "text",
						"text": "File contents read successfully from /tmp by AgentMesh Downstream!",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	})

	log.Println("Mock Downstream MCP Server running on 127.0.0.1:9000...")
	http.ListenAndServe("127.0.0.1:9000", nil)
}