"""PydanticAI agent with cryptographically signed tool calls."""

from __future__ import annotations

import sys
from dataclasses import dataclass

from pydantic_ai import Agent, RunContext
from rich.console import Console
from rich.text import Text

from single_agent import tools
from single_agent.audit import append_envelope, clear, read_all, save_agent_key
from single_agent.signing import make_agent, sign_tool_call

console = Console()


@dataclass
class Deps:
    did: str
    priv_hex: str


_agent = Agent(
    "openai:gpt-4o-mini",
    deps_type=Deps,
    system_prompt=(
        "You are a data analyst assistant. "
        "Use the available tools to fulfill the user's request. "
        "Be concise — one short paragraph max."
    ),
)


def _record(ctx: RunContext[Deps], tool_name: str, args: dict) -> None:
    """Sign a tool invocation and append it to the audit log."""
    envelope = sign_tool_call(ctx.deps.priv_hex, ctx.deps.did, tool_name, args)
    append_envelope(envelope)

    display_args = ", ".join(
        f"{k}={repr(v[:40] + '...' if isinstance(v, str) and len(v) > 40 else v)}"
        for k, v in args.items()
    )
    line = Text()
    line.append(f"[agent] Calling: {tool_name}", style="cyan")
    line.append(f"({display_args})", style="dim")
    line.append("   ✓ signed", style="green bold")
    console.print(line)


@_agent.tool
def read_csv(ctx: RunContext[Deps], path: str) -> str:
    """Read a CSV file and return its contents."""
    _record(ctx, "read_csv", {"path": path})
    return tools.read_csv(path)


@_agent.tool
def summarize(ctx: RunContext[Deps], data: str) -> str:
    """Summarize the provided data."""
    _record(ctx, "summarize", {"data": data})
    return tools.summarize(data)


@_agent.tool
def write_report(ctx: RunContext[Deps], path: str, content: str) -> bool:
    """Write a report to the given file path."""
    _record(ctx, "write_report", {"path": path, "content": content})
    return tools.write_report(path, content)


@_agent.tool
def send_notification(ctx: RunContext[Deps], channel: str, message: str) -> bool:
    """Send a notification to a channel."""
    _record(ctx, "send_notification", {"channel": channel, "message": message})
    return tools.send_notification(channel, message)


def main() -> None:
    prompt = (
        " ".join(sys.argv[1:])
        or "Read data/sales.csv, summarize it, and send a notification to the team channel."
    )

    clear()
    did, pub_hex, priv_hex = make_agent()
    save_agent_key(did, pub_hex)

    console.print(f"\n[bold]Agent identity:[/bold] [dim]{did}[/dim]")
    console.print(f"[bold]Task:[/bold] {prompt}\n")

    result = _agent.run_sync(prompt, deps=Deps(did=did, priv_hex=priv_hex))

    console.print(f"\n[bold]Result:[/bold] {result.output}\n")

    entries = read_all()
    console.print(f"[green]✓[/green] {len(entries)} action(s) signed by [dim]{did}[/dim]")
    console.print("[dim]Run [bold]verify-log[/bold] to verify the audit trail.[/dim]\n")
