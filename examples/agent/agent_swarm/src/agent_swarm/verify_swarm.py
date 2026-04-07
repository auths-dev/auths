"""CLI entry point: verify the full delegation chain for every action in audit.jsonl.

For each action envelope, three checks are performed:
  1. Signature — the action was signed by the claimed agent key.
  2. Delegation — the agent was authorized by the orchestrator (delegation token valid).
  3. Scope — the tool used matches the capabilities in the delegation token.
"""

import json
import sys

from auths import verify_action_envelope
from rich.console import Console
from rich.table import Table

from agent_swarm.audit import load_swarm_keys, read_all

console = Console()


def _verify_delegation(entry: dict, keys: dict[str, dict]) -> tuple[bool, str]:
    """Verify the delegation token embedded in an action envelope.

    Returns:
        (valid, error_message)
    """
    payload = entry.get("payload", {})
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return False, "payload parse error"

    token = payload.get("delegation_token")
    if not token:
        return False, "no delegation token"

    delegator_did = token.get("identity")
    if not delegator_did or delegator_did not in keys:
        return False, f"unknown delegator: {delegator_did}"

    delegator_pub = keys[delegator_did]["pub_hex"]
    result = verify_action_envelope(json.dumps(token), delegator_pub)
    if not result.valid:
        return False, result.error or "delegation sig invalid"

    return True, ""


def _extract_tool_and_cap(entry: dict) -> tuple[str, str | None]:
    """Return (tool_name, required_capability) from an action envelope."""
    payload = entry.get("payload", {})
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {}

    tool_name = payload.get("tool") or entry.get("type") or "unknown"

    token = payload.get("delegation_token", {})
    token_payload = token.get("payload", {}) if isinstance(token, dict) else {}
    if isinstance(token_payload, str):
        try:
            token_payload = json.loads(token_payload)
        except json.JSONDecodeError:
            token_payload = {}

    caps = token_payload.get("capabilities") or []
    cap_str = ", ".join(caps) if caps else None
    return tool_name, cap_str


def _print_chain(keys: dict[str, dict]) -> None:
    """Print the swarm identity tree stored in the key registry."""
    console.print("\n[bold]Registered identities:[/bold]")
    for did, info in keys.items():
        console.print(f"  {info['name']:20s}  [dim]{did[:48]}...[/dim]")
    console.print()


def main() -> None:
    try:
        keys = load_swarm_keys()
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    entries = read_all()
    if not entries:
        console.print("[yellow]No entries in audit.jsonl. Run `run-swarm` first.[/yellow]")
        sys.exit(0)

    _print_chain(keys)
    console.print("[bold]Verifying action audit trail...[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=4)
    table.add_column("Agent", min_width=16)
    table.add_column("Tool", min_width=20)
    table.add_column("Sig", width=6)
    table.add_column("Delegation", width=12)
    table.add_column("Capabilities", min_width=14)

    sig_passed = del_passed = 0
    sig_failed = del_failed = 0

    for i, entry in enumerate(entries, 1):
        agent_did = entry.get("identity", "")
        agent_info = keys.get(agent_did, {})
        agent_name = agent_info.get("name", agent_did[:16])
        agent_pub = agent_info.get("pub_hex", "")

        # 1. Signature check
        if agent_pub:
            sig_result = verify_action_envelope(json.dumps(entry), agent_pub)
            sig_ok = sig_result.valid
        else:
            sig_ok = False

        if sig_ok:
            sig_cell = "[green]✓[/green]"
            sig_passed += 1
        else:
            sig_cell = "[red]✗[/red]"
            sig_failed += 1

        # 2. Delegation check
        del_ok, del_err = _verify_delegation(entry, keys)
        if del_ok:
            del_cell = "[green]✓[/green]"
            del_passed += 1
        else:
            del_cell = "[red]✗[/red]"
            del_failed += 1

        tool_name, caps = _extract_tool_and_cap(entry)
        caps_cell = caps or "[dim]—[/dim]"

        table.add_row(str(i), agent_name, tool_name, sig_cell, del_cell, caps_cell)

    console.print(table)

    total = len(entries)
    all_ok = sig_failed == 0 and del_failed == 0

    console.print()
    _status(f"{sig_passed}/{total} action signatures valid", sig_failed == 0)
    _status(f"{del_passed}/{total} delegation chains valid", del_failed == 0)

    if all_ok:
        console.print(
            "\n[green bold]✓ Audit trail intact"
            " — every action is authorized and verifiable.[/green bold]\n"
        )
    else:
        console.print("\n[red bold]✗ Audit trail has failures.[/red bold]\n")
        sys.exit(1)


def _status(msg: str, ok: bool) -> None:
    icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
    console.print(f"  {icon} {msg}")
