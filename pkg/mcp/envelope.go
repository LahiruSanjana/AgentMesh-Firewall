package mcp

import (
	"encoding/json"
	"errors"
)

type MessageType string 

const (
	CodeParseError = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams = -32602
	CodeInternalError = -32603

	// Agent Mesh customer error
	CodePolicyError = -32001
	CodeApprovalTimeout = -32002
    CodeApprovalRejected = -32003
	CodeTenantScopeViolation = -32004
)

const (
	MessageTypeUnknown MessageType = "UNKONWN"
	MessageTypeRequest MessageType = "REQUEST"
	MessageTypeNotification MessageType = "NOTIFICATION"
	MessageTypeResponse MessageType = "RESPONSE"
)

type RPCError struct {
	Code   int     `json:"code"`
	Message string `json:"message"`
	Data    *json.RawMessage `json:"data,omitempty"`
}

type Envelope struct {
	JSONRPC  string     `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  *string          `json:"method,omitempty"`
	Params  *json.RawMessage `json:"params,omitempty"`
	Result  *json.RawMessage `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
}

var (
	ErrInvalidJSONRPC = errors.New("jsonrpc version must be exactly '2.0'")
	ErrMissingMethodOrResult = errors.New("must contain either method (request) or result/error (response)")
	ErrAmbiguousPayload = errors.New("cannot contain both method and result/error simultaneously")
	ErrInvalidErrorObj = errors.New("error response must have non-zero code and non empty message")
)

func (e *Envelope) Validate() error {
	if e.JSONRPC != "2.0" {
		return ErrInvalidJSONRPC
	}

	hasMethod := e.Method != nil && *e.Method != ""
	hasResultOrError := e.Result != nil || e.Error != nil

	if hasMethod && hasResultOrError {
		return ErrAmbiguousPayload
	}

	if !hasMethod && !hasResultOrError {
		return ErrMissingMethodOrResult
	}

	if e.Error != nil {
		if e.Result != nil {
			return ErrAmbiguousPayload
		}
		if e.Error.Code == 0 || e.Error.Message == "" {
			return ErrInvalidErrorObj
		}
	}

	return nil
}


func (e *Envelope) Classify() (MessageType, error) {

    if err := e.Validate(); err != nil {
		return MessageTypeUnknown, err
	}

	hasID := e.ID != nil 
	hasMethod := e.Method != nil && *e.Method != ""
	hasResultOrError := e.Result != nil || e.Error != nil

	if hasMethod && hasID {
		return MessageTypeRequest, nil
	}

	if hasMethod && !hasID {
		return MessageTypeNotification, nil
	}

	if hasResultOrError && hasID {
		return MessageTypeResponse, nil
	}

	return MessageTypeUnknown, errors.New("unable to classify envelope")
}