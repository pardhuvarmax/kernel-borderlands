# KB MCP Subsystem (`kb-op/kb-mcp/`)

This directory houses the Model Context Protocol (MCP) server integration for Kernel Borderlands. It acts as an API gateway for AI agents, allowing external LLM engines and the AADS agent swarm to safely inspect system states and invoke containment actions.

---

## 1. Subsystem Architecture

```mermaid
flowchart TD
    subgraph AI Client
        LLM[LLM / Agent Engine]
    end
    
    subgraph kb-mcp (MCP Server)
        StdIO[stdio Transport]
        Handler[Tool Request Dispatcher]
    end
    
    subgraph Control Plane
        KBD[Go Control Plane Daemon]
        gRPC(gRPC API)
    end
    
    LLM -->|JSON-RPC 2.0| StdIO
    StdIO --> Handler
    Handler -->|gRPC Call| gRPC
    gRPC --> KBD
```

The server implements the standard MCP specification using a bidirectional **stdio transport** protocol. It translates incoming JSON-RPC tool calls into secure gRPC requests routed directly to the `kb-control-plane` daemon.

---

## 2. Exposed MCP Tools

AI clients connecting to `kb-mcp` gain access to these kernel management tools:

| Tool Name | Parameters | Description |
|---|---|---|
| `get_system_status` | None | Retrieves general stats, loaded eBPF maps status, and overall threat levels. |
| `list_active_processes` | None | Returns a list of monitored PIDs, threat zones, and behavioral risk scores. |
| `get_process_lineage` | `pid` (integer) | Fetches execution parentage and historical telemetry logs for a target PID. |
| `quarantine_process` | `pid` (integer), `reason` (string) | Triggers BPF LSM blocking rules to contain a compromised process. |

---

## 3. Operations & Configuration

### Running the MCP Host
The MCP server communicates using JSON-RPC over standard input/output. It can be initialized by any MCP client (such as Cursor, Claude Desktop, or custom Python agent scripts).

```bash
# Navigate to MCP directory
cd kb-op/kb-mcp

# Build the MCP server binary (Go implementation)
go build -o kb-mcp main.go

# Run the server (will expect stdin/stdout communication)
./kb-mcp
```

### Integration in Client Configuration
To connect this MCP server to a desktop workspace client (e.g. Claude Desktop app), add the configuration below to the configuration file:

```json
{
  "mcpServers": {
    "kernel-borderlands": {
      "command": "/home/emergence/Desktop/kernel-borderlands/kb-op/kb-mcp/kb-mcp",
      "args": []
    }
  }
}
```
