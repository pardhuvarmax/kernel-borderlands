package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
)

type JSONRPCRequest struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *JSONRPCError    `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ToolCallResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

func getSystemStatistics(client pb.KernelBorderlandsClient) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := client.GetSystemStats(ctx, &pb.Empty{})
	if err != nil {
		return "", err
	}

	payload, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func main() {
	log.SetOutput(os.Stderr)
	log.Println("MCP server starting...")

	socketPath := os.Getenv("KB_GRPC_SOCKET")
	if socketPath == "" {
		socketPath = "/run/kb/kba.sock"
	}

	dialTarget := fmt.Sprintf("unix://%s", socketPath)
	conn, err := grpc.Dial(dialTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to dial gRPC: %v", err)
	}
	defer conn.Close()

	client := pb.NewKernelBorderlandsClient(conn)

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			sendError(nil, -32700, "Parse error", err.Error())
			continue
		}

		handleRequest(&req, client)
	}
}

func handleRequest(req *JSONRPCRequest, client pb.KernelBorderlandsClient) {
	switch req.Method {
	case "initialize":
		res := map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]string{
				"name":    "kb-mcp",
				"version": "0.1.0",
			},
		}
		sendResponse(req.ID, res)

	case "notifications/initialized":
		// No-op

	case "tools/list":
		res := ToolsListResult{
			Tools: []Tool{
				{
					Name:        "kb.get_statistics",
					Description: "Returns global telemetry stats and process volumes.",
					InputSchema: map[string]interface{}{
						"type":       "object",
						"properties": map[string]interface{}{},
					},
				},
			},
		}
		sendResponse(req.ID, res)

	case "tools/call":
		var params ToolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			sendError(req.ID, -32602, "Invalid params", err.Error())
			return
		}

		if params.Name == "kb.get_statistics" {
			statsStr, err := getSystemStatistics(client)
			if err != nil {
				sendResponse(req.ID, ToolCallResult{
					Content: []TextContent{
						{
							Type: "text",
							Text: fmt.Sprintf("Error fetching system stats: %v", err),
						},
					},
					IsError: true,
				})
				return
			}
			sendResponse(req.ID, ToolCallResult{
				Content: []TextContent{
					{
						Type: "text",
						Text: statsStr,
					},
				},
			})
		} else {
			sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", params.Name), nil)
		}

	default:
		sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method), nil)
	}
}

func sendResponse(id *json.RawMessage, result interface{}) {
	res := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	bytes, _ := json.Marshal(res)
	fmt.Println(string(bytes))
}

func sendError(id *json.RawMessage, code int, msg string, data interface{}) {
	res := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: msg,
			Data:    data,
		},
	}
	bytes, _ := json.Marshal(res)
	fmt.Println(string(bytes))
}
