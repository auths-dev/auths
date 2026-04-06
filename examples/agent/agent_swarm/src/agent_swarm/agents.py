"""Orchestrator + sub-agent swarm with cryptographically signed tool calls.

The orchestrator is a PydanticAI agent. Each of its tools delegates to a
specialized sub-agent, which signs the action with its own key and embeds its
delegation token. Every action in the audit log is traceable to the human
who bootstrapped the swarm.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from pydantic_ai import Agent, RunContext
from rich.console import Console
from rich.text import Text

from agent_swarm import tools
from agent_swarm.audit import append_envelope, clear, read_all, save_swarm_keys
from agent_swarm.identities import SwarmIdentity, make_swarm
from agent_swarm.signing import CapabilityError, sign_tool_call

console = Console()


@dataclass
class OrchestratorDeps:
    data_agent: SwarmIdentity
    analysis_agent: SwarmIdentity
    notify_agent: SwarmIdentity


_orchestrator = Agent(
    "openai:gpt-4o-mini",
    deps_type=OrchestratorDeps,
    system_prompt=(
        "You are a data analyst orchestrator. "
        "Coordinate your specialized sub-agents to fulfill the user's request. "
        "Use read_data to fetch data, analyze_data to summarize it, "
        "and send_notification to deliver results. "
        "Be concise — one short paragraph max."
    ),
)


def _record(agent: SwarmIdentity, tool_name: str, args: dict, cap: str) -> None:
    """Sign the tool call and append it to the audit log; print status line."""
    envelope = sign_tool_call(agent, tool_name, args, cap)
    append_envelope(envelope)

    display_args = ", ".join(
        f"{k}={repr(v[:40] + '...' if isinstance(v, str) and len(v) > 40 else v)}"
        for k, v in args.items()
    )
    line = Text()
    line.append(f"  [{agent.name}] ", style="bold cyan")
    line.append(f"{tool_name}({display_args})", style="dim")
    line.append("   ✓ signed", style="green bold")
    console.print(line)


@_orchestrator.tool
def read_data(ctx: RunContext[OrchestratorDeps], path: str) -> str:
    """Read data from a CSV file (delegated to DataAgent)."""
    _record(ctx.deps.data_agent, "read_csv", {"path": path}, "read_data")
    return tools.read_csv(path)


@_orchestrator.tool
def analyze_data(ctx: RunContext[OrchestratorDeps], data: str) -> str:
    """Summarize the provided data (delegated to AnalysisAgent)."""
    _record(ctx.deps.analysis_agent, "summarize", {"data": data}, "analyze")
    return tools.summarize(data)


@_orchestrator.tool
def send_notification(ctx: RunContext[OrchestratorDeps], channel: str, message: str) -> bool:
    """Send a notification to a channel (delegated to NotifyAgent)."""
    args = {"channel": channel, "message": message}
    _record(ctx.deps.notify_agent, "send_notification", args, "notify")
    return tools.send_notification(channel, message)


def _print_identity_tree(
    human: SwarmIdentity,
    orchestrator: SwarmIdentity,
    sub_agents: list[SwarmIdentity],
) -> None:
    console.print("\n[bold]Swarm identity chain:[/bold]")
    console.print(f"  [yellow]{human.name}[/yellow]  [dim]{human.did[:40]}...[/dim]")
    caps = ", ".join(orchestrator.capabilities)
    did_abbrev = orchestrator.did[:40]
    console.print(f"  └─ [cyan]{orchestrator.name}[/cyan]  [dim]{did_abbrev}...[/dim]  [{caps}]")
    for i, agent in enumerate(sub_agents):
        prefix = "└─" if i == len(sub_agents) - 1 else "├─"
        caps = ", ".join(agent.capabilities)
        console.print(
            f"       {prefix} [green]{agent.name}[/green]"
            f"  [dim]{agent.did[:40]}...[/dim]  [{caps}]"
        )
    console.print()


def _demo_scope_violation(sub_agents: list[SwarmIdentity]) -> None:
    """Show that a sub-agent cannot exceed its granted capabilities."""
    data_agent = sub_agents[0]
    console.print("[bold]Scope enforcement demo:[/bold]")
    console.print(
        f"  Attempting to use [green]{data_agent.name}[/green] for a"
        " [red]'notify'[/red] action it was never granted..."
    )
    try:
        sign_tool_call(data_agent, "send_notification", {"channel": "team", "message": "hi"}, "notify")  # noqa: E501
        console.print("  [red]ERROR: scope check did not fire[/red]")
    except CapabilityError as e:
        console.print(f"  [green]✓ Blocked:[/green] [dim]{e}[/dim]\n")


def main() -> None:
    prompt = (
        " ".join(sys.argv[1:])
        or "Read data/sales.csv, analyze it, and send a summary notification to the team channel."
    )

    clear()
    human, orchestrator, sub_agents = make_swarm()
    data_agent, analysis_agent, notify_agent = sub_agents

    save_swarm_keys(human, orchestrator, sub_agents)
    _print_identity_tree(human, orchestrator, sub_agents)
    _demo_scope_violation(sub_agents)

    console.print(f"[bold]Task:[/bold] {prompt}\n")

    result = _orchestrator.run_sync(
        prompt,
        deps=OrchestratorDeps(
            data_agent=data_agent,
            analysis_agent=analysis_agent,
            notify_agent=notify_agent,
        ),
    )

    console.print(f"\n[bold]Result:[/bold] {result.output}\n")

    entries = read_all()
    signed_dids = {e.get("identity") for e in entries}
    agent_count = len(signed_dids)

    console.print(f"[green]✓[/green] {len(entries)} action(s) across {agent_count} agent(s)")
    console.print("[dim]Run [bold]verify-swarm[/bold] to verify the full delegation chain.[/dim]\n")
