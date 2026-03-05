"""Auths agent identity for Python AI frameworks.

Usage with LangChain:
    from auths_agent import AuthsAgentAuth

    auth = AuthsAgentAuth(
        bridge_url="https://oidc.example.com",
        attestation_chain_path="~/.auths-agent/chain.json",
    )

    # Get Bearer token for MCP tool access
    token = auth.get_token(capabilities=["fs:read", "web:search"])

Usage with CrewAI:
    from auths_agent import AuthsAgentAuth

    auth = AuthsAgentAuth(
        bridge_url="https://oidc.example.com",
        attestation_chain_path="~/.auths-agent/chain.json",
    )
    headers = {"Authorization": f"Bearer {auth.get_token(['fs:read'])}"}
"""

from auths_agent.auth import AuthsAgentAuth

__all__ = ["AuthsAgentAuth"]
