# MCP OAuth Demo

A demonstration of OAuth 2.0 authentication with the Model Context Protocol (MCP), showcasing separated Authorization Server/Resource Server architecture using oAuths

---

## Overview

This project demonstrates how to implement OAuth 2.0 authentication for MCP servers and clients using:

- **Authorization Server (AS)**: Handles OAuth flows, client registration, and token issuance
- **Resource Server (RS)**: Validates tokens via introspection and serves protected MCP resources  
- **MCP Client**: Authenticates using OAuth and connects to protected MCP servers

---

## How to Run

1. Start the Authorization Server

```bash
cd simple-auth
uv run mcp-simple-auth-as --port=9000
```

2. Start the Resource Server

```bash
cd simple-auth
uv run mcp-simple-auth-rs --port=8001 --auth-server=http://localhost:9000 --transport=streamable-http
```

3. Run the Client

```bash
cd simple-auth-client
MCP_SERVER_PORT=8001 MCP_TRANSPORT_TYPE=streamable_http uv run mcp-simple-auth-client
```
---

### Project Structure

```
oauth-demo/
├── simple-auth/                    # Authorization & Resource Server
│   ├── mcp_simple_auth/
│   │   ├── auth_server.py         # Authorization Server
│   │   ├── server.py              # Resource Server  
│   │   ├── simple_auth_provider.py # OAuth provider (demo provider)
│   │   └── token_verifier.py      # Token introspection
│   └── pyproject.toml
├── simple-auth-client/             # MCP Client
│   ├── mcp_simple_auth_client/
│   │   └── main.py                # OAuth client
│   └── pyproject.toml
└── README.md
```

---

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MCP Client    │─── │ Authorization   │─── │  Resource       │
│                 │    │ Server (AS)     │    │  Server (RS)    │
│ - OAuth flow    │    │ - User auth     │    │ - Token verify  │
│ - Token storage │    │ - Token issue   │    │ - MCP tools     │
│ - MCP calls     │    │ - Introspection │    │ - Protected API │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

Note: This oAuth flow contains hardcoded vatriables for demonstration. Don't use it as its for production! 



