"""
Simple OAuth provider for MCP servers.

This module contains a basic OAuth implementation using hardcoded user credentials
for demonstration purposes. No external authentication provider is required.

NOTE: This is not a production-ready implementation.

"""

import logging
import secrets
import time
from typing import Any

from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)


class SimpleAuthSettings(BaseSettings):
    """Simple OAuth settings for demo purposes."""

    model_config = SettingsConfigDict(env_prefix="MCP_")

    # Demo user credentials
    demo_username: str = "devloper_harsh"
    demo_password: str = "admin@2000"

    # MCP OAuth scope
    mcp_scope: str = "user"


class SimpleOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """
    Simple OAuth provider for demo purposes.

    This provider handles the OAuth flow by:
    1. Providing a simple login form for demo credentials
    2. Showing a consent screen for resource access
    3. Issuing MCP tokens after successful authentication and consent
    4. Maintaining token state for introspection
    """

    def __init__(self, settings: SimpleAuthSettings, auth_callback_url: str, server_url: str):
        self.settings = settings
        self.auth_callback_url = auth_callback_url
        self.server_url = server_url
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}
        self.state_mapping: dict[str, dict[str, str | None]] = {}
        # Store authenticated user information and consent data
        self.user_data: dict[str, dict[str, Any]] = {}
        self.pending_consent: dict[str, dict[str, Any]] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Generate an authorization URL for simple login flow."""
        state = params.state or secrets.token_hex(16)

        # Store state mapping for callback
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(params.redirect_uri_provided_explicitly),
            "client_id": client.client_id,
            "resource": params.resource,  # RFC 8707
        }

        # Build simple login URL that points to login page
        auth_url = f"{self.auth_callback_url}?state={state}&client_id={client.client_id}"

        return auth_url

    async def get_login_page(self, state: str) -> HTMLResponse:
        """Generate login page HTML for the given state."""
        if not state:
            raise HTTPException(400, "Missing state parameter")

        # Create simple login form HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MCP Demo Authentication</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }}
                .form-group {{ margin-bottom: 15px; }}
                input {{ width: 100%; padding: 8px; margin-top: 5px; }}
                button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }}
            </style>
        </head>
        <body>
            <h2>MCP Demo Authentication</h2>
            <p>Enter your Username & Password to Authenticate. Use the demo credentials below:</p>
            <p><strong>Username:</strong> devloper_harsh<br>
            <strong>Password:</strong> admin@2000</p>

            <form action="{self.server_url.rstrip("/")}/login/callback" method="post">
                <input type="hidden" name="state" value="{state}">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" value="demo_user" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" value="demo_password" required>
                </div>
                <button type="submit">Sign In</button>
            </form>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    async def get_consent_page(self, consent_token: str) -> HTMLResponse:
        """Generate consent page HTML for the given consent token."""
        if not consent_token or consent_token not in self.pending_consent:
            raise HTTPException(400, "Invalid or missing consent token")

        consent_data = self.pending_consent[consent_token]
        
        # Define the tools that will be accessible
        available_tools = [
            {
                "name": "get_time",
                "description": "Get the current server time and timezone information"
            },
            {
                "name": "calculator", 
                "description": "Perform mathematical calculations with support for basic and advanced operations"
            },
            {
                "name": "get_weather",
                "description": "Get current weather information for any city (simulated data)"
            }
        ]

        tools_html = ""
        for tool in available_tools:
            tools_html += f"""
            <div style="border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px;">
                <strong>{tool['name']}</strong><br>
                <span style="color: #666; font-size: 14px;">{tool['description']}</span>
            </div>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MCP Resource Access Consent</title>
            <style>
                body {{ 
                    font-family: Arial, sans-serif; 
                    max-width: 600px; 
                    margin: 0 auto; 
                    padding: 20px; 
                    background-color: #f9f9f9;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                }}
                .client-info {{
                    background: #f0f8ff;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .permissions {{
                    margin: 20px 0;
                }}
                .tool-list {{
                    max-height: 300px;
                    overflow-y: auto;
                    border: 1px solid #eee;
                    border-radius: 5px;
                    padding: 10px;
                }}
                .disclaimer {{
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 10px;
                    border-radius: 5px;
                    margin: 20px 0;
                    font-size: 14px;
                }}
                .buttons {{
                    text-align: center;
                    margin-top: 30px;
                }}
                .approve-btn {{
                    background-color: #28a745;
                    color: white;
                    padding: 12px 30px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                    margin-right: 15px;
                }}
                .approve-btn:hover {{
                    background-color: #218838;
                }}
                .deny-btn {{
                    background-color: #dc3545;
                    color: white;
                    padding: 12px 30px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                }}
                .deny-btn:hover {{
                    background-color: #c82333;
                }}
                .user-info {{
                    background: #e8f5e8;
                    padding: 10px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>🔐 Resource Access Consent</h2>
                    <p>An application is requesting access to your MCP resources</p>
                </div>

                <div class="user-info">
                    <strong>Authenticated User:</strong> {consent_data['username']}
                </div>

                <div class="client-info">
                    <h3>Application Details</h3>
                    <p><strong>Client:</strong> {consent_data['client_name']}</p>
                    <p><strong>Requesting Access To:</strong> MCP Tools and Resources</p>
                </div>

                <div class="permissions">
                    <h3>📋 Available Tools & Resources</h3>
                    <p>This application will be able to access the following tools on your behalf:</p>
                    <div class="tool-list">
                        {tools_html}
                    </div>
                </div>

                <div class="disclaimer">
                    <strong>⚠️ Important:</strong> Only approve resource access for applications you trust. 
                    The application will be able to execute these tools and access their data using your credentials.
                </div>

                <div class="buttons">
                    <form action="{self.server_url.rstrip("/")}/consent/callback" method="post" style="display: inline;">
                        <input type="hidden" name="consent_token" value="{consent_token}">
                        <input type="hidden" name="action" value="approve">
                        <button type="submit" class="approve-btn">✅ Approve Access</button>
                    </form>
                    
                    <form action="{self.server_url.rstrip("/")}/consent/callback" method="post" style="display: inline;">
                        <input type="hidden" name="consent_token" value="{consent_token}">
                        <input type="hidden" name="action" value="deny">
                        <button type="submit" class="deny-btn">❌ Deny Access</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    async def handle_login_callback(self, request: Request) -> Response:
        """Handle login form submission callback."""
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        state = form.get("state")

        if not username or not password or not state:
            raise HTTPException(400, "Missing username, password, or state parameter")

        # Ensure we have strings, not UploadFile objects
        if not isinstance(username, str) or not isinstance(password, str) or not isinstance(state, str):
            raise HTTPException(400, "Invalid parameter types")

        # Validate demo credentials
        if username != self.settings.demo_username or password != self.settings.demo_password:
            raise HTTPException(401, "Invalid credentials")

        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        # Create consent token and store pending consent data
        consent_token = f"consent_{secrets.token_hex(16)}"
        client = await self.get_client(state_data["client_id"])
        
        self.pending_consent[consent_token] = {
            "username": username,
            "state": state,
            "client_name": client.client_name if client else "Unknown Application",
            "authenticated_at": time.time()
        }

        # Redirect to consent page
        consent_url = f"{self.server_url.rstrip('/')}/consent?token={consent_token}"
        return RedirectResponse(url=consent_url, status_code=302)

    async def handle_consent_callback(self, request: Request) -> Response:
        """Handle consent form submission callback."""
        form = await request.form()
        consent_token = form.get("consent_token")
        action = form.get("action")

        if not consent_token or not action:
            raise HTTPException(400, "Missing consent token or action")

        if not isinstance(consent_token, str) or not isinstance(action, str):
            raise HTTPException(400, "Invalid parameter types")

        consent_data = self.pending_consent.get(consent_token)
        if not consent_data:
            raise HTTPException(400, "Invalid or expired consent token")

        state = consent_data["state"]
        username = consent_data["username"]

        if action == "deny":
            # Clean up consent data but keep state mapping for potential retry
            del self.pending_consent[consent_token]
            
            # Create a denial page with option to retry consent
            state_data = self.state_mapping.get(state)
            retry_url = f"{self.server_url.rstrip('/')}/login?state={state}&client_id={state_data['client_id']}" if state_data else "#"
            
            return HTMLResponse(content=f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
                <style>
                    body {{ 
                        font-family: Arial, sans-serif; 
                        max-width: 500px; 
                        margin: 50px auto; 
                        padding: 20px; 
                        text-align: center;
                        background-color: #f9f9f9;
                    }}
                    .container {{
                        background: white;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }}
                    .error {{ 
                        color: #dc3545; 
                        margin-bottom: 20px;
                    }}
                    .message {{
                        margin: 20px 0;
                        line-height: 1.6;
                    }}
                    .retry-btn {{ 
                        background-color: #007bff; 
                        color: white; 
                        padding: 12px 24px; 
                        border: none; 
                        border-radius: 5px; 
                        cursor: pointer; 
                        margin: 10px;
                        text-decoration: none;
                        display: inline-block;
                        font-size: 16px;
                    }}
                    .retry-btn:hover {{
                        background-color: #0056b3;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2 class="error">❌ Access Denied</h2>
                    <div class="message">
                        <p>You have denied access to the requested resources.</p>
                        <p>To use the application, you must approve the resource access request.</p>
                        <p><strong>Would you like to try again?</strong></p>
                    </div>
                    <div>
                        <a href="{retry_url}" class="retry-btn">🔄 Try Again</a>
                    </div>
                </div>
            </body>
            </html>
            """, status_code=403)

        elif action == "approve":
            # Clean up consent data
            del self.pending_consent[consent_token]
            
            # Continue with authorization code flow
            redirect_uri = await self.handle_simple_callback(username, "", state, skip_auth=True)
            return RedirectResponse(url=redirect_uri, status_code=302)

        else:
            raise HTTPException(400, "Invalid action")

    async def handle_simple_callback(self, username: str, password: str, state: str, skip_auth: bool = False) -> str:
        """Handle simple authentication callback and return redirect URI."""
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = state_data["redirect_uri_provided_explicitly"] == "True"
        client_id = state_data["client_id"]
        resource = state_data.get("resource")  # RFC 8707

        # These are required values from our own state mapping
        assert redirect_uri is not None
        assert code_challenge is not None
        assert client_id is not None

        # Validate demo credentials (skip if already authenticated via consent flow)
        if not skip_auth and (username != self.settings.demo_username or password != self.settings.demo_password):
            raise HTTPException(401, "Invalid credentials")

        # Create MCP authorization code
        new_code = f"mcp_{secrets.token_hex(16)}"
        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=[self.settings.mcp_scope],
            code_challenge=code_challenge,
            resource=resource,  # RFC 8707
        )
        self.auth_codes[new_code] = auth_code

        # Store user data
        self.user_data[username] = {
            "username": username,
            "user_id": f"user_{secrets.token_hex(8)}",
            "authenticated_at": time.time(),
        }

        # Only delete state mapping after successful completion
        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an authorization code."""
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        # Generate MCP access token
        mcp_token = f"mcp_{secrets.token_hex(32)}"

        # Store MCP token
        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
            resource=authorization_code.resource,  # RFC 8707
        )

        # Store user data mapping for this token
        self.user_data[mcp_token] = {
            "username": self.settings.demo_username,
            "user_id": f"user_{secrets.token_hex(8)}",
            "authenticated_at": time.time(),
        }

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        # Check if expired
        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        """Load a refresh token - not supported in this example."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token - not supported in this example."""
        raise NotImplementedError("Refresh tokens not supported")

    # TODO(Marcelo): The type hint is wrong. We need to fix, and test to check if it works.
    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:  # type: ignore
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]
